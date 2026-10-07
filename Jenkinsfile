pipeline {
  agent { label 'windows-msys2' }
  options { timestamps(); disableConcurrentBuilds() }
  triggers { pollSCM('H/2 * * * *') }
  stages {
    stage('Checkout') {
      steps {
        checkout scm
        script {
          def BASH = 'C:\\msys64\\usr\\bin\\bash.exe'
          env.GIT_SHA  = env.GIT_COMMIT.take(7)
          env.GIT_SHA_FULL = env.GIT_COMMIT
          bat(script: "${BASH} -c \"git fetch --tags --force >/dev/null 2>&1 || true\"", returnStatus: true)
          env.GIT_TAG   = bat(script: "${BASH} -c \"git describe --tags --abbrev=0 2>/dev/null || true\"", returnStdout: true).trim()
          env.GIT_EXACT = bat(script: "${BASH} -c \"git describe --tags --exact-match 2>/dev/null || true\"", returnStdout: true).trim()
          env.GIT_DESC  = bat(script: "${BASH} -c \"git describe --tags --always\"", returnStdout: true).trim()
        }
      }
    }
    stage('Build (MSYS2 UCRT64)') {
      steps {
        script {
          def bv = (env.GIT_TAG ?: 'v0.0.0').trim()
          def cm = (env.GIT_SHA_FULL ?: '').trim()
          def s = """set -euo pipefail
export MSYSTEM=UCRT64
export PATH="/ucrt64/bin:/usr/bin:/bin:\$PATH"
export NSISDIR=/ucrt64/share/nsis
git submodule update --init --recursive
export COMMIT="${cm}"
export BUILD_VERSION="${bv}"
cmake -B build -G Ninja -S . -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_DOCS=OFF -DSUNSHINE_ASSETS_DIR=assets -DSUNSHINE_PUBLISHER_NAME=LegionGames -DSUNSHINE_PUBLISHER_WEBSITE=https://legiongames.ru -DSUNSHINE_PUBLISHER_ISSUE_URL=https://legiongames.ru
ninja -C build
mkdir -p artifacts
cd build
cpack -G NSIS
cpack -G ZIP
mv ./cpack_artifacts/Sunshine.exe ../artifacts/Sunshine-Windows-AMD64-installer.exe
mv ./cpack_artifacts/Sunshine.zip ../artifacts/Sunshine-Windows-AMD64-portable.zip
"""
          def b64 = s.getBytes('UTF-8').encodeBase64().toString()
          bat "C:\\msys64\\usr\\bin\\bash.exe -eo pipefail -c \"echo ${b64} | base64 -d | bash -eo pipefail\""
        }
      }
    }
    stage('Archive') {
      steps {
        archiveArtifacts artifacts: 'artifacts/**', fingerprint: true
        stash name: 'artifacts', includes: 'artifacts/**'
      }
    }
    stage('Publish to pkgs') {
      agent { label 'controller' }
      steps {
        unstash 'artifacts'
        script {
          def tag   = (env.GIT_TAG ?: 'v0.0.0').trim()
          def exact = (env.GIT_EXACT ?: '').trim()
          def desc  = (env.GIT_DESC ?: '').trim()
          def sha   = (env.GIT_SHA ?: '').trim()
          def full  = (env.GIT_SHA_FULL ?: '').trim()
          if (!sha) { error 'No commit SHA available from SCM.' }
          def verNoV = tag.startsWith('v') ? tag.substring(1) : tag
          def dirName = exact ? exact : "${tag}-${sha}"
          def base = '/pkgs/sunshine'
          def vdir = "${base}/${dirName}"
          sh "mkdir -p ${vdir}"
          sh "cp artifacts/Sunshine-Windows-AMD64-installer.exe ${vdir}/"
          sh "cp artifacts/Sunshine-Windows-AMD64-portable.zip ${vdir}/ || true"
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
  "channel": "stable",
  "min_supported": "0.0.0",
  "released_at": "${ts}",
  "assets": {
    "windows": {
      "url": "https://pkgs.legiongames.ru/sunshine/latest/Sunshine-Windows-AMD64-installer.exe",
      "sha256": "${h}",
      "size": ${sz}
    }
  }
}
"""
          writeFile file: "${vdir}/manifest.json", text: manifest
          writeFile file: "${vdir}/version", text: sha
          sh "cd ${base} && ln -sfn ${dirName} latest.new && mv -T latest.new latest"
          echo "Published sunshine ${dirName}: version=${verNoV} commit=${sha} build=${env.BUILD_NUMBER}"
        }
      }
    }
  }
}
