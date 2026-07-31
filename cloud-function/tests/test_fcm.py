"""Tests for FCM push notification helpers (app/fcm.py).

FCM messaging calls are mocked to avoid real network calls.
Firestore is mocked as a nested dict tree to support
collection → document → subcollection → document chains.
"""

import time
import pytest
from unittest.mock import MagicMock, patch, ANY


@pytest.fixture
def mock_db():
    """Dict-backed Firestore mock with proper nested subcollection support.

    Layout: db._tree[collection][doc_id] = doc_data
            subcollections live at: db._tree[collection][doc_id]._sc[name] = {...}
    """
    db = MagicMock()
    db._tree = {}  # {collection_name: {doc_id: user_data_or_sc_data}}

    def _snapshot(doc_id, data, data_parent=None):
        """Create a DocumentSnapshot-like mock."""
        snap = MagicMock()
        snap.id = doc_id
        snap.to_dict.return_value = dict(data) if data else {}
        snap.exists = True

        def _get(key):
            return data.get(key) if isinstance(data, dict) else None

        snap.get = _get
        snap.reference = MagicMock()
        snap.reference.id = doc_id

        if data_parent is not None and isinstance(data, dict):
            def _ref_update(update_data):
                data.update(update_data)

            snap.reference.update = _ref_update

        return snap

    def _collection(col_name):
        if col_name not in db._tree:
            db._tree[col_name] = {}
        col_data = db._tree[col_name]

        col = MagicMock()
        col._col_name = col_name

        def _document(doc_id):
            if doc_id not in col_data:
                col_data[doc_id] = {}

            doc = MagicMock()
            doc.id = doc_id
            doc._col_name = col_name
            doc.__doc_data = col_data[doc_id]  # raw dict ref

            def _set(data):
                col_data[doc_id] = data

            def _update(data):
                if isinstance(col_data[doc_id], dict):
                    col_data[doc_id].update(data)
                else:
                    col_data[doc_id] = data

            def _delete():
                col_data.pop(doc_id, None)

            def _collection(sub_name):
                """Get subcollection: creates nested storage under doc."""
                sc_key = f"_sc_{sub_name}"
                if sc_key not in col_data[doc_id]:
                    col_data[doc_id][sc_key] = {}
                sc_data = col_data[doc_id][sc_key]

                sc = MagicMock()
                sc._col_name = sub_name

                def _sc_document(sc_doc_id=None):
                    if sc_doc_id is None:
                        sc_doc_id = f"auto_{len(sc_data)}"
                    if sc_doc_id not in sc_data:
                        sc_data[sc_doc_id] = {}

                    sc_doc = MagicMock()
                    sc_doc.id = sc_doc_id

                    def _sc_set(data):
                        sc_data[sc_doc_id] = data

                    def _sc_update(data):
                        sc_data[sc_doc_id].update(data)

                    def _sc_delete():
                        sc_data.pop(sc_doc_id, None)

                    sc_doc.set = _sc_set
                    sc_doc.update = _sc_update
                    sc_doc.delete = _sc_delete
                    sc_doc._data = sc_data[sc_doc_id]
                    return sc_doc

                def _sc_stream():
                    snaps = []
                    for d_id, d_data in sc_data.items():
                        snaps.append(_snapshot(d_id, d_data))
                    return snaps

                def _sc_where(field, op, value):
                    q = MagicMock()
                    q._limit_val = None

                    def _limit(n):
                        q._limit_val = n
                        return q

                    def _get_results():
                        results = []
                        for d_id, d_data in sc_data.items():
                            if op == "==" and d_data.get(field) == value:
                                results.append(_snapshot(d_id, d_data, sc_data))
                        if q._limit_val is not None:
                            results = results[:q._limit_val]
                        return results

                    def _stream():
                        return _get_results()

                    q.limit = _limit
                    q.get = _get_results
                    q.stream = _stream
                    return q

                sc.document = _sc_document
                sc.stream = _sc_stream
                sc.where = _sc_where
                return sc

            doc.collection = _collection
            doc.set = _set
            doc.update = _update
            doc.delete = _delete
            return doc

        def _stream():
            snaps = []
            for d_id, d_data in col_data.items():
                # Skip internal subcollection keys
                if not d_id.startswith("_sc_"):
                    snaps.append(_snapshot(d_id, d_data))
            return snaps

        def _add(data):
            auto_id = f"auto_{len([k for k in col_data if not k.startswith('_sc_')])}"
            col_data[auto_id] = data
            doc = MagicMock()
            doc.id = auto_id
            return doc

        col.document = _document
        col.stream = _stream
        col.add = _add
        return col

    db.collection = _collection
    return db


class TestStoreDeviceToken:
    def test_stores_new_token(self, mock_db):
        from app.fcm import store_device_token

        doc_id = store_device_token(mock_db, "user1", "token_abc")
        assert doc_id is not None

        # Now query for it
        devices = (
            mock_db.collection("users")
            .document("user1")
            .collection("devices")
            .where("token", "==", "token_abc")
            .limit(1)
            .get()
        )
        assert len(devices) == 1
        assert devices[0].get("token") == "token_abc"
        assert devices[0].get("is_active") is True

    def test_updates_existing_token(self, mock_db):
        from app.fcm import store_device_token

        store_device_token(mock_db, "user1", "token_abc", device_name="Phone")
        store_device_token(mock_db, "user1", "token_abc", device_name="Phone v2")

        devices = (
            mock_db.collection("users")
            .document("user1")
            .collection("devices")
            .where("token", "==", "token_abc")
            .limit(1)
            .get()
        )
        assert len(devices) == 1
        assert devices[0].get("device_name") == "Phone v2"

    def test_stores_multiple_devices_different_tokens(self, mock_db):
        from app.fcm import store_device_token

        store_device_token(mock_db, "user1", "token_abc", app_type="user")
        store_device_token(mock_db, "user1", "token_xyz", app_type="admin")

        from app.fcm import get_active_tokens_for_user

        tokens = get_active_tokens_for_user(mock_db, "user1")
        assert len(tokens) == 2
        assert "token_abc" in tokens
        assert "token_xyz" in tokens


class TestGetActiveTokens:
    def test_returns_empty_for_no_devices(self, mock_db):
        from app.fcm import get_active_tokens_for_user

        tokens = get_active_tokens_for_user(mock_db, "user_none")
        assert tokens == []

    def test_excludes_inactive_devices(self, mock_db):
        from app.fcm import store_device_token, deactivate_device_token, get_active_tokens_for_user

        store_device_token(mock_db, "user1", "token_active")
        store_device_token(mock_db, "user1", "token_inactive")

        deactivate_device_token(mock_db, "user1", "token_inactive")

        tokens = get_active_tokens_for_user(mock_db, "user1")
        assert tokens == ["token_active"]

    def test_deduplicates_same_token(self, mock_db):
        from app.fcm import get_active_tokens_for_user

        # Store same token twice (simulating corrupt data)
        mock_db.collection("users").document("user1").collection("devices").document("d1").set({
            "token": "token_dup", "is_active": True,
        })
        mock_db.collection("users").document("user1").collection("devices").document("d2").set({
            "token": "token_dup", "is_active": True,
        })

        tokens = get_active_tokens_for_user(mock_db, "user1")
        assert tokens == ["token_dup"]


class TestDeactivateDeviceToken:
    def test_deactivates_existing_token(self, mock_db):
        from app.fcm import store_device_token, deactivate_device_token

        store_device_token(mock_db, "user1", "token_deact")
        result = deactivate_device_token(mock_db, "user1", "token_deact")
        assert result is True

    def test_returns_false_for_nonexistent_token(self, mock_db):
        from app.fcm import deactivate_device_token

        result = deactivate_device_token(mock_db, "user1", "token_ghost")
        assert result is False


class TestBuildUnlockMulticast:
    def test_builds_message_with_required_fields(self):
        from app.fcm import build_unlock_multicast

        msg = build_unlock_multicast(
            tokens=["token1"],
            user_id="user1",
            confidence="HIGH",
            similarity=0.87,
        )

        assert msg.tokens == ["token1"]
        assert msg.notification is not None
        assert msg.notification.title == "Door Unlocked"
        assert "unlocked (high confidence)" in msg.notification.body
        assert msg.data["type"] == "unlock_event"
        assert msg.data["user_id"] == "user1"
        assert msg.data["confidence"] == "HIGH"
        assert msg.data["similarity"] == "0.87"

    def test_pin_method_title(self):
        from app.fcm import build_unlock_multicast

        msg = build_unlock_multicast(
            tokens=["token1"],
            user_id="user1",
            confidence="N/A",
            similarity=0.0,
            method="PIN",
        )

        assert "PIN" in msg.notification.body

    def test_android_high_priority(self):
        from app.fcm import build_unlock_multicast

        msg = build_unlock_multicast(
            tokens=["token1"], user_id="x", confidence="HIGH", similarity=0.9,
        )
        assert msg.android.priority == "high"
        assert msg.android.ttl == 60

    def test_apns_content_available(self):
        from app.fcm import build_unlock_multicast

        msg = build_unlock_multicast(
            tokens=["token1"], user_id="x", confidence="HIGH", similarity=0.9,
        )
        assert msg.apns.payload.aps.content_available is True


class TestSendUnlockNotification:
    @patch("firebase_admin.messaging.send_each_for_multicast")
    def test_sends_multicast_for_active_tokens(self, mock_send, mock_db):
        from app.fcm import store_device_token, send_unlock_notification

        store_device_token(mock_db, "user1", "token_a")
        store_device_token(mock_db, "user1", "token_b")

        mock_response = MagicMock()
        mock_response.success_count = 2
        mock_response.failure_count = 0
        mock_response.responses = [MagicMock(success=True), MagicMock(success=True)]
        mock_send.return_value = mock_response

        result = send_unlock_notification(
            mock_db, "user1", confidence="HIGH", similarity=0.95,
        )

        assert result["success"] == 2
        assert result["failure"] == 0
        assert result["cleaned"] == 0
        mock_send.assert_called_once()

    @patch("firebase_admin.messaging.send_each_for_multicast")
    def test_no_tokens_skips_send(self, mock_send, mock_db):
        from app.fcm import send_unlock_notification

        result = send_unlock_notification(
            mock_db, "user_none", confidence="HIGH", similarity=0.95,
        )

        assert result["success"] == 0
        assert result["failure"] == 0
        mock_send.assert_not_called()

    @patch("firebase_admin.messaging.send_each_for_multicast")
    def test_cleans_invalid_tokens(self, mock_send, mock_db):
        from app.fcm import store_device_token, send_unlock_notification, get_active_tokens_for_user
        from firebase_admin import messaging

        store_device_token(mock_db, "user1", "token_bad")

        mock_response = MagicMock()
        mock_response.success_count = 0
        mock_response.failure_count = 1

        bad_resp = MagicMock(success=False)
        bad_resp.exception = messaging.UnregisteredError("bad token", "invalid")
        mock_response.responses = [bad_resp]

        mock_send.return_value = mock_response

        result = send_unlock_notification(
            mock_db, "user1", confidence="HIGH", similarity=0.95,
        )

        assert result["cleaned"] == 1
        # Token should now be inactive
        tokens = get_active_tokens_for_user(mock_db, "user1")
        assert tokens == []

    @patch("firebase_admin.messaging.send_each_for_multicast")
    def test_does_not_clean_transient_errors(self, mock_send, mock_db):
        from app.fcm import store_device_token, send_unlock_notification, get_active_tokens_for_user

        store_device_token(mock_db, "user1", "token_transient")

        mock_response = MagicMock()
        mock_response.success_count = 0
        mock_response.failure_count = 1

        bad_resp = MagicMock(success=False)
        bad_resp.exception = Exception("Some transient error")
        mock_response.responses = [bad_resp]

        mock_send.return_value = mock_response

        result = send_unlock_notification(
            mock_db, "user1", confidence="HIGH", similarity=0.95,
        )

        assert result["cleaned"] == 0
        # Token should still be active
        tokens = get_active_tokens_for_user(mock_db, "user1")
        assert tokens == ["token_transient"]

    @patch("firebase_admin.messaging.send_each_for_multicast")
    def test_handles_send_exception_gracefully(self, mock_send, mock_db):
        from app.fcm import store_device_token, send_unlock_notification

        store_device_token(mock_db, "user1", "token_error")

        mock_send.side_effect = RuntimeError("FCM down")

        result = send_unlock_notification(
            mock_db, "user1", confidence="HIGH", similarity=0.95,
        )

        assert result["success"] == 0
        assert result["failure"] == 1
        assert result["cleaned"] == 0
