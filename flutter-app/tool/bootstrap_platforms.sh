#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v flutter >/dev/null 2>&1 || {
  printf 'ERROR: Flutter SDK is required.\n' >&2
  exit 1
}

cd "${APP_DIR}"
flutter create \
  --platforms=android,ios \
  --org=com.bipulprasadjain \
  --project-name=smart_ai_home_lock_frontend \
  .

ANDROID_BUILD="${APP_DIR}/android/app/build.gradle.kts"
if [[ -f "${ANDROID_BUILD}" ]]; then
  sed -i 's/minSdk = flutter.minSdkVersion/minSdk = 24/' "${ANDROID_BUILD}"
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
  PLIST="${APP_DIR}/ios/Runner/Info.plist"
  PLIST_BUDDY="/usr/libexec/PlistBuddy"
  if [[ -x "${PLIST_BUDDY}" && -f "${PLIST}" ]]; then
    "${PLIST_BUDDY}" -c \
      "Add :NSCameraUsageDescription string Capture five face enrollment photos." \
      "${PLIST}" 2>/dev/null || true
    "${PLIST_BUDDY}" -c \
      "Add :NSPhotoLibraryUsageDescription string Select face enrollment photos." \
      "${PLIST}" 2>/dev/null || true
  fi
fi

printf 'Flutter Android/iOS platform projects are ready.\n'
