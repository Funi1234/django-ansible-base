from __future__ import annotations

import logging
import uuid as _uuid_module
from dataclasses import dataclass
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db.models import Q

from ansible_base.lib.utils.apps import is_rbac_installed
from ansible_base.resource_registry.models import Resource

logger = logging.getLogger('ansible_base.rbac.role_sync_utils')

__all__ = [
    'AssignmentTuple',
    'create_local_assignment',
    'delete_local_assignment',
    'get_ansible_id_or_pk',
    'get_content_object',
    'get_local_assignments',
]


@dataclass
class AssignmentTuple:
    """Represents an assignment as a 4-tuple for set comparison."""

    actor_ansible_id: str  # user_ansible_id or team_ansible_id
    ansible_id_or_pk: str | None  # object_id or object_ansible_id (None for global)
    role_definition_name: str
    assignment_type: str  # 'user' or 'team'

    def __hash__(self):
        return hash((self.actor_ansible_id, self.ansible_id_or_pk, self.role_definition_name, self.assignment_type))

    def __eq__(self, other):
        if not isinstance(other, AssignmentTuple):
            return False
        return (
            self.actor_ansible_id == other.actor_ansible_id
            and self.ansible_id_or_pk == other.ansible_id_or_pk
            and self.role_definition_name == other.role_definition_name
            and self.assignment_type == other.assignment_type
        )


def get_ansible_id_or_pk(assignment) -> str:
    """Resolve the ansible_id or raw PK for an assignment's target object.

    Looks up the object's ``ansible_id`` via the Resource table for all
    content types that have a registry entry, so local tuples carry the same
    UUID that Gateway sends in ``object_ansible_id``.  Falls back to the raw
    ``object_id`` for types without a Resource entry.  Raises for
    organization/team objects that are missing a Resource entry, as those
    must always be registered.
    """
    if not is_rbac_installed():
        raise RuntimeError("get_ansible_id_or_pk requires ansible_base.rbac to be installed")
    object_resource = Resource.objects.filter(
        object_id=assignment.object_id,
        content_type__app_label=assignment.content_type.app_label,
        content_type__model=assignment.content_type.model,
    ).first()
    if object_resource:
        return str(object_resource.ansible_id)
    if assignment.content_type.model in ('organization', 'team'):
        raise RuntimeError(f"Error: {assignment.content_type.model} {assignment.object_id} was found without an associated Resource.")
    return str(assignment.object_id)


def get_content_object(role_definition, assignment_tuple: AssignmentTuple) -> Any:
    """Resolve the Django model instance for an assignment tuple's target object."""
    if not is_rbac_installed():
        raise RuntimeError("get_content_object requires ansible_base.rbac to be installed")
    if role_definition.content_type is None:
        raise ValueError("get_content_object requires a role_definition with a content_type")
    # Try Resource registry first — handles UUID ansible_ids from Gateway for all content types,
    # not only organization and team.  Only attempt when the value is a valid UUID; integer PKs
    # would cause a UUIDField ValidationError in the filter.
    try:
        _uuid_module.UUID(str(assignment_tuple.ansible_id_or_pk))
        resource = Resource.objects.filter(ansible_id=assignment_tuple.ansible_id_or_pk).first()
        if resource is not None:
            return resource.content_object
    except (ValueError, AttributeError):
        pass
    model = role_definition.content_type.model_class()
    return model.objects.get(pk=assignment_tuple.ansible_id_or_pk)


def _bulk_resolve_actor_ansible_ids(assignments: list, actor_attr: str) -> dict[str, str]:
    """Build a ``{str(pk): str(ansible_id)}`` map for all actors in a single query.

    *actor_attr* is ``'user'`` or ``'team'`` — the FK attribute name on the
    assignment model.
    """
    if not assignments:
        return {}

    actor_pks = {str(getattr(a, f'{actor_attr}_id')) for a in assignments}
    first_actor = getattr(assignments[0], actor_attr)
    actor_ct_id = ContentType.objects.get_for_model(first_actor).pk

    return {
        str(obj_id): str(ansible_id)
        for obj_id, ansible_id in Resource.objects.filter(
            object_id__in=actor_pks,
            content_type_id=actor_ct_id,
        ).values_list('object_id', 'ansible_id')
    }


def _bulk_resolve_object_ansible_ids(assignments: list) -> dict[tuple[str, str, str], str]:
    """Build a ``{(str(object_id), app_label, model): str(ansible_id)}`` map for all resource-registered objects.

    Resolves ansible_ids for every content type that has a Resource entry,
    not only organization and team.  The caller falls back to the raw
    ``object_id`` for types with no entry in the result map.

    Keys on ``(object_id, app_label, model)`` rather than ``(object_id, model)``
    to avoid collisions when two DABContentType services share a model name.
    """
    object_ids: set[str] = set()
    app_labels: set[str] = set()
    model_names: set[str] = set()
    for a in assignments:
        if a.object_id and a.content_type:
            object_ids.add(str(a.object_id))
            app_labels.add(a.content_type.app_label)
            model_names.add(a.content_type.model)

    if not object_ids:
        return {}

    return {
        (str(obj_id), app_label, model): str(ansible_id)
        for obj_id, app_label, model, ansible_id in Resource.objects.filter(
            object_id__in=object_ids,
            content_type__app_label__in=app_labels,
            content_type__model__in=model_names,
        ).values_list('object_id', 'content_type__app_label', 'content_type__model', 'ansible_id')
    }


_SKIP = object()


def _resolve_object_ansible_id(assignment, object_map: dict[tuple[str, str, str], str]):
    """Resolve the ansible_id or pk for an assignment's target object.

    Returns ``None`` for global assignments, the resolved ansible_id if one
    exists in the Resource registry, the raw ``object_id`` for types without
    a registry entry, or the sentinel ``_SKIP`` if an org/team object is
    missing a Resource entry (those must always be registered).
    """
    if not assignment.object_id or not assignment.content_type:
        return None

    model_name = assignment.content_type.model
    key = (str(assignment.object_id), assignment.content_type.app_label, model_name)
    resolved = object_map.get(key)
    if resolved is not None:
        return resolved

    if model_name in ('organization', 'team'):
        logger.error(f"{model_name} {assignment.object_id} found without an associated Resource, skipping assignment.")
        return _SKIP

    # For types without a Resource registry entry, fall back to the raw integer PK.
    return str(assignment.object_id)


def _collect_assignment_tuples(
    assignment_list: list,
    actor_attr: str,
    assignment_type: str,
) -> set[AssignmentTuple]:
    """Convert a list of Django assignment model instances into AssignmentTuples.

    Resolves actor and object ansible_ids in bulk, then builds tuples.
    Skips assignments whose actor lacks a Resource entry.
    """
    actor_map = _bulk_resolve_actor_ansible_ids(assignment_list, actor_attr)
    object_map = _bulk_resolve_object_ansible_ids(assignment_list)
    result: set[AssignmentTuple] = set()

    for a in assignment_list:
        actor_pk = str(getattr(a, f'{actor_attr}_id'))
        actor_ansible_id = actor_map.get(actor_pk)
        if actor_ansible_id is None:
            continue

        ansible_id_or_pk = _resolve_object_ansible_id(a, object_map)
        if ansible_id_or_pk is _SKIP:
            continue

        result.add(
            AssignmentTuple(
                actor_ansible_id=actor_ansible_id,
                ansible_id_or_pk=ansible_id_or_pk,
                role_definition_name=a.role_definition.name,
                assignment_type=assignment_type,
            )
        )

    return result


def get_local_assignments(service: str | None = None) -> set[AssignmentTuple]:
    """Get local role assignments as a set of tuples for set-diff comparison.

    Args:
        service: Optional service name (e.g. ``"controller"``, ``"hub"``,
            ``"eda"``) to filter assignments by ``content_type__service``.
            Global assignments (``content_type=None``) are always included.
            When ``None`` (default), all assignments are returned.

    Returns:
        A set of ``AssignmentTuple`` instances representing the local
        role assignments.  Assignments whose actor (user/team) lacks a
        corresponding ``Resource`` entry are silently skipped.
    """
    if not is_rbac_installed():
        raise RuntimeError("get_local_assignments requires ansible_base.rbac to be installed")
    from ansible_base.rbac.models.role import RoleTeamAssignment, RoleUserAssignment

    service_filter = Q()
    if service:
        service_filter = Q(content_type__service=service) | Q(content_type__isnull=True)

    assignments: set[AssignmentTuple] = set()
    for model, actor_attr, assignment_type in (
        (RoleUserAssignment, 'user', 'user'),
        (RoleTeamAssignment, 'team', 'team'),
    ):
        qs = model.objects.select_related(actor_attr, 'role_definition', 'content_type')
        if service:
            qs = qs.filter(service_filter)
        assignments |= _collect_assignment_tuples(list(qs), actor_attr, assignment_type)

    return assignments


def delete_local_assignment(assignment_tuple: AssignmentTuple) -> bool:
    """Delete a local assignment based on the tuple."""
    if not is_rbac_installed():
        raise RuntimeError("delete_local_assignment requires ansible_base.rbac to be installed")
    from ansible_base.rbac.models.role import RoleDefinition

    try:
        role_definition = RoleDefinition.objects.get(name=assignment_tuple.role_definition_name)

        resource = Resource.objects.get(ansible_id=assignment_tuple.actor_ansible_id)
        actor = resource.content_object

        content_object = None
        if assignment_tuple.ansible_id_or_pk:
            content_object = get_content_object(role_definition, assignment_tuple)
        if content_object:
            role_definition.remove_permission(actor, content_object)
        else:
            role_definition.remove_global_permission(actor)

        return True

    except Exception:
        logger.exception(f"Failed to delete assignment {assignment_tuple}")
        return False


def create_local_assignment(assignment_tuple: AssignmentTuple) -> bool:
    """Create a local assignment based on the tuple."""
    if not is_rbac_installed():
        raise RuntimeError("create_local_assignment requires ansible_base.rbac to be installed")
    from ansible_base.rbac.models.role import RoleDefinition

    try:
        role_definition = RoleDefinition.objects.get(name=assignment_tuple.role_definition_name)

        resource = Resource.objects.get(ansible_id=assignment_tuple.actor_ansible_id)
        actor = resource.content_object

        content_object = None
        if assignment_tuple.ansible_id_or_pk:
            content_object = get_content_object(role_definition, assignment_tuple)
        if content_object:
            role_definition.give_permission(actor, content_object)
        else:
            role_definition.give_global_permission(actor)

        return True

    except Exception:
        logger.exception(f"Failed to create assignment {assignment_tuple}")
        return False
