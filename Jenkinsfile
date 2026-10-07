pipeline {
  agent { label 'windows-msys2' }
  options { timestamps(); disableConcurrentBuilds() }
  triggers { pollSCM('H/2 * * * *') }
  stages {
    stage('Checkout') {
      steps { checkout scm }
    }
    stage('Build (MSYS2 UCRT64)') {
      steps {
        writeFile file: 'ci-build-sunshine.sh', text: '''set -euo pipefail
export MSYSTEM=UCRT64
export PATH="/ucrt64/bin:/usr/bin:/bin:$PATH"
export NSISDIR=/ucrt64/share/nsis
git submodule sync --recursive >/dev/null 2>&1 || true
if [ ! -f third-party/moonlight-common-c/CMakeLists.txt ]; then
  git submodule update --init --recursive --jobs 8
fi
TAG="$(git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0)"
EXACT="$(git describe --tags --exact-match 2>/dev/null || echo)"
DESC="$(git describe --tags --always 2>/dev/null || echo)"
COMMIT="$(git rev-parse HEAD)"
SHORT="$(git rev-parse --short=7 HEAD)"
printf 'TAG=%s\nEXACT=%s\nDESC=%s\nCOMMIT=%s\nSHORT=%s\n' "$TAG" "$EXACT" "$DESC" "$COMMIT" "$SHORT" > ci-meta.properties
export BUILD_VERSION="$TAG"
export COMMIT="$COMMIT"
cmake -B build -G Ninja -S . -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_DOCS=OFF -DSUNSHINE_ASSETS_DIR=assets -DSUNSHINE_PUBLISHER_NAME=LegionGames -DSUNSHINE_PUBLISHER_WEBSITE=https://legiongames.ru -DSUNSHINE_PUBLISHER_ISSUE_URL=https://legiongames.ru
ninja -C build
mkdir -p artifacts
cd build
cpack -G NSIS
cpack -G ZIP
mv ./cpack_artifacts/Sunshine.exe ../artifacts/Sunshine-Windows-AMD64-installer.exe
mv ./cpack_artifacts/Sunshine.zip ../artifacts/Sunshine-Windows-AMD64-portable.zip
'''
        bat "C:\\msys64\\usr\\bin\\bash.exe -c \"tr -d '\\r' < ci-build-sunshine.sh > .ci-build.sh && bash -eo pipefail .ci-build.sh\""
      }
    }
    stage('Archive') {
      steps {
        archiveArtifacts artifacts: 'artifacts/**', fingerprint: true
        stash name: 'artifacts', includes: 'artifacts/**, ci-meta.properties'
      }
    }
    stage('Publish (edge, commit-keyed)') {
      agent { label 'controller' }
      steps {
        unstash 'artifacts'
        script {
          def meta = readProperties file: 'ci-meta.properties'
          def tag   = (meta.TAG ?: '').trim()
          def desc  = (meta.DESC ?: '').trim()
          def sha   = (meta.SHORT ?: '').trim()
          def full  = (meta.COMMIT ?: '').trim()
          if (!sha) { error 'No commit SHA available.' }
          def verNoV = tag.startsWith('v') ? tag.substring(1) : (tag ?: '0.0.0')
          def base = '/pkgs/sunshine'
          def cdir = "${base}/commits/${sha}"
          sh "mkdir -p ${cdir}"
          sh "cp artifacts/Sunshine-Windows-AMD64-installer.exe ${cdir}/"
          sh "cp artifacts/Sunshine-Windows-AMD64-portable.zip ${cdir}/ || true"
          def exe = 'artifacts/Sunshine-Windows-AMD64-installer.exe'
          def h = sh(script: "sha256sum ${exe} | cut -d' ' -f1", returnStdout: true).trim()
          def sz = sh(script: "stat -c %s ${exe}", returnStdout: true).trim()
          def ts = sh(script: "date -u +%Y-%m-%dT%H:%M:%SZ", returnStdout: true).trim()
          def manifest = """{
  "version": "${verNoV}",
  "tag": "${tag}",
  "commit": "${sha}",
  "commit_full": "${full}",
  "describe": "${desc}",
  "build": ${env.BUILD_NUMBER},
  "channel": "edge",
  "min_supported": "0.0.0",
  "released_at": "${ts}",
  "assets": {
    "windows": {
      "url": "https://pkgs.legiongames.ru/sunshine/edge/latest/Sunshine-Windows-AMD64-installer.exe",
      "sha256": "${h}",
      "size": ${sz}
    }
  }
}
"""
          writeFile file: "${cdir}/manifest.json", text: manifest
          writeFile file: "${cdir}/version", text: sha
          sh "mkdir -p ${base}/edge && cd ${base}/edge && ln -sfn ../commits/${sha} latest.new && mv -T latest.new latest"
          echo "Published edge ${sha}: version=${verNoV} commit=${sha} build=${env.BUILD_NUMBER}"
        }
      }
    }
  }
}
