from __future__ import annotations

import pytest

from scripts.consts import MANAGED_TAG
from scripts.reconciler import build_plan

from .conftest import make_vega, make_yaml


def test_identical_detection_is_a_no_op(yaml_detection, vega_detection):
    plan = build_plan([yaml_detection], [vega_detection])
    assert plan.no_op_updates == 1
    assert not plan.creates and not plan.updates and not plan.deletes
    assert plan.unmanaged == 0


def test_new_yaml_is_created_in_its_state():
    plan = build_plan([make_yaml(state="disabled")], [])
    assert len(plan.creates) == 1
    assert plan.creates[0]["state"] == "DISABLED"
    assert plan.creates[0]["tags"] == [MANAGED_TAG]


def test_mode_change_is_an_update(yaml_detection, vega_detection):
    plan = build_plan([dict(yaml_detection, mode="evidence")], [vega_detection])
    assert len(plan.updates) == 1
    assert plan.updates[0]["mode"] == "EVIDENCE"


def test_skill_change_is_an_update_and_same_set_is_not(yaml_detection):
    current = make_vega(skills=[{"id": "s1"}, {"id": "s2"}])
    assert build_plan([dict(yaml_detection, skillIds=["s2", "s1"])], [current]).no_op_updates == 1
    plan = build_plan([yaml_detection], [current])
    assert plan.updates[0]["skillIds"] == []


def test_missing_description_in_yaml_never_diffs(yaml_detection):
    current = make_vega(logicDescription="kept", attackScenario="kept too")
    assert build_plan([yaml_detection], [current]).no_op_updates == 1


def test_pre_tag_managed_detection_is_retagged_keeping_ui_tags(yaml_detection):
    current = make_vega(tags=["team:soc"])
    plan = build_plan([yaml_detection], [current])
    assert len(plan.updates) == 1
    assert plan.updates[0]["tags"] == ["team:soc", MANAGED_TAG]


def test_retag_is_not_sent_when_marker_present(yaml_detection):
    plan = build_plan([dict(yaml_detection, severity=1)], [make_vega(tags=["team:soc", MANAGED_TAG])])
    assert len(plan.updates) == 1
    assert "tags" not in plan.updates[0]


def test_only_tagged_non_library_orphans_are_deleted(yaml_detection, vega_detection):
    library = make_vega(id="lib", externalId="lib-ext", tags=[], createdBy={"principalType": "vega_library"})
    library_tagged = make_vega(id="libtag", externalId="libtag-ext", tags=[MANAGED_TAG], createdBy={"principalType": "vega_library"})
    ui_rule = make_vega(id="ui", externalId="ui-ext", tags=["team:soc"])
    retired = make_vega(id="old", externalId="old-ext")
    plan = build_plan([yaml_detection], [vega_detection, library, library_tagged, ui_rule, retired])
    assert [d["externalId"] for d in plan.deletes] == ["old-ext"]
    assert plan.unmanaged == 3


def test_missing_tags_and_created_by_are_treated_as_unmanaged(yaml_detection):
    orphan = make_vega(id="x", externalId="x-ext", tags=None, createdBy=None)
    plan = build_plan([yaml_detection], [orphan])
    assert not plan.deletes
    assert plan.unmanaged == 1


def test_yaml_pointing_at_a_library_detection_is_refused(yaml_detection):
    library = make_vega(createdBy={"principalType": "vega_library"})
    with pytest.raises(ValueError, match="Vega library detection"):
        build_plan([yaml_detection], [library])


def test_ui_built_detection_is_adopted_by_matching_id(yaml_detection):
    current = make_vega(tags=["team:soc"], createdBy={"principalType": "user"})
    plan = build_plan([yaml_detection], [current])
    assert len(plan.updates) == 1
    assert plan.updates[0]["externalId"] == yaml_detection["id"]
    assert plan.updates[0]["tags"] == ["team:soc", MANAGED_TAG]
