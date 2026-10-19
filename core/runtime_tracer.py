from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


WIN32_RESOURCE_FRIDA_SCRIPT = r"""
'use strict';

// Resource-Studio Dynamic Runtime Observation Script
// Hooks Win32 user32.dll & kernel32.dll resource APIs to capture dynamic resource loads.

const user32 = Process.getModuleByName('user32.dll');
const kernel32 = Process.getModuleByName('kernel32.dll');

function resolveResourceIdentifier(ptrVal) {
    const val = ptrVal.toUInt32();
    if (val <= 0xFFFF) {
        return { kind: 'ID', value: val };
    }
    try {
        const strVal = ptrVal.readUtf16String();
        return { kind: 'NAME', value: strVal };
    } catch (e) {
        return { kind: 'POINTER', value: ptrVal.toString() };
    }
}

// 1. Hook LoadStringW
const pLoadStringW = user32.findExportByName('LoadStringW');
if (pLoadStringW) {
    Interceptor.attach(pLoadStringW, {
        onEnter: function (args) {
            this.hInst = args[0];
            this.uID = args[1].toUInt32();
            this.buffer = args[2];
        },
        onLeave: function (retval) {
            let loadedText = null;
            if (retval.toInt32() > 0 && !this.buffer.isNull()) {
                try {
                    loadedText = this.buffer.readUtf16String(retval.toInt32());
                } catch (e) {}
            }
            send({
                event: 'LOAD_STRING',
                api: 'LoadStringW',
                resourceType: 'STRING',
                resourceId: this.uID,
                textLength: retval.toInt32(),
                text: loadedText,
                hInstance: this.hInst.toString()
            });
        }
    });
}

// 2. Hook FindResourceW
const pFindResourceW = kernel32.findExportByName('FindResourceW');
if (pFindResourceW) {
    Interceptor.attach(pFindResourceW, {
        onEnter: function (args) {
            const nameIdent = resolveResourceIdentifier(args[1]);
            const typeIdent = resolveResourceIdentifier(args[2]);
            send({
                event: 'FIND_RESOURCE',
                api: 'FindResourceW',
                resourceType: typeIdent.value,
                resourceName: nameIdent.value,
                resourceNameKind: nameIdent.kind,
                hModule: args[0].toString()
            });
        }
    });
}

// 3. Hook CreateDialogParamW
const pCreateDialogParamW = user32.findExportByName('CreateDialogParamW');
if (pCreateDialogParamW) {
    Interceptor.attach(pCreateDialogParamW, {
        onEnter: function (args) {
            const tmplIdent = resolveResourceIdentifier(args[1]);
            send({
                event: 'CREATE_DIALOG',
                api: 'CreateDialogParamW',
                resourceType: 'DIALOG',
                templateName: tmplIdent.value,
                templateKind: tmplIdent.kind,
                dialogProc: args[3].toString(),
                hInstance: args[0].toString()
            });
        }
    });
}

// 4. Hook LoadImageW
const pLoadImageW = user32.findExportByName('LoadImageW');
if (pLoadImageW) {
    Interceptor.attach(pLoadImageW, {
        onEnter: function (args) {
            const nameIdent = resolveResourceIdentifier(args[1]);
            const uType = args[2].toUInt32();
            const typeName = uType === 1 ? 'IMAGE_ICON' : (uType === 2 ? 'IMAGE_CURSOR' : 'IMAGE_BITMAP');
            send({
                event: 'LOAD_IMAGE',
                api: 'LoadImageW',
                resourceType: typeName,
                name: nameIdent.value,
                nameKind: nameIdent.kind,
                cx: args[3].toInt32(),
                cy: args[4].toInt32(),
                hInstance: args[0].toString()
            });
        }
    });
}
"""


@dataclass(frozen=True)
class RuntimeObservationEvent:
    event_type: str
    api_name: str
    resource_type: str
    resource_id_or_name: Any
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "eventType": self.event_type,
            "apiName": self.api_name,
            "resourceType": self.resource_type,
            "resource": self.resource_id_or_name,
            "details": self.details,
        }


class RuntimeTracer:
    """
    Generates and coordinates runtime dynamic observation of Win32 resource APIs
    using Frida instrumentation scripts to resolve dynamic and obfuscated resource IDs.
    """

    @staticmethod
    def get_frida_script() -> str:
        """Returns the complete inline Frida instrumentation script."""
        return WIN32_RESOURCE_FRIDA_SCRIPT.strip()

    @staticmethod
    def parse_event(raw_message: dict[str, Any]) -> RuntimeObservationEvent | None:
        """Parses a message received from the Frida interceptor into a typed event."""
        payload = raw_message.get("payload") if "payload" in raw_message else raw_message
        if not isinstance(payload, dict) or "event" not in payload:
            return None

        event_type = payload.get("event", "UNKNOWN")
        api = payload.get("api", "UNKNOWN")
        res_type = payload.get("resourceType", "UNKNOWN")
        res_val = payload.get("resourceId") or payload.get("resourceName") or payload.get("templateName") or payload.get("name")

        return RuntimeObservationEvent(
            event_type=event_type,
            api_name=api,
            resource_type=res_type,
            resource_id_or_name=res_val,
            details=payload,
        )
