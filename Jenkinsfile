// =============================================================================
// Detection-as-Code CD pipeline
//
// Git (PR + branch protection) is the CI gate. This pipeline is the CD half:
// it validates, plans both clusters, gates on approval, then rolls DC -> DR
// and proves parity afterwards.
//
// Branches:
//   PR / feature  -> validate + plan only (no apply)
//   main          -> validate + plan + approval + apply DC + apply DR + parity
// =============================================================================

pipeline {
  agent { label 'terraform' }

  options {
    timestamps()
    ansiColor('xterm')
    buildDiscarder(logRotator(numToKeepStr: '50'))
    disableConcurrentBuilds()          // never let two applies race on one state
    timeout(time: 60, unit: 'MINUTES')
  }

  parameters {
    booleanParam(name: 'SKIP_DR',      defaultValue: false, description: 'Apply DC only (DR in maintenance).')
    booleanParam(name: 'AUTO_APPROVE', defaultValue: false, description: 'Skip the manual gate (break-glass only).')
    string(name: 'MAX_DESTROY',        defaultValue: '3',   description: 'Fail if the plan destroys more than this many resources.')
  }

  environment {
    TF_IN_AUTOMATION  = 'true'
    TF_INPUT          = '0'
    TF_DIR            = 'terraform/deployments/detections'
    RULE_ID_NAMESPACE = credentials('elastic-dac-rule-id-namespace')
    MANAGED_TAG       = 'Managed: Terraform'
  }

  stages {

    stage('Checkout') {
      steps {
        checkout scm
        sh 'git --no-pager log -1 --pretty="%h %an %s"'
      }
    }

    // -------------------------------------------------------------------
    // PRE-CHECKS - everything that can fail without touching a cluster
    // -------------------------------------------------------------------
    stage('Pre-checks') {
      parallel {

        stage('Rule content validation') {
          steps {
            sh '''
              python3 -m venv .venv && . .venv/bin/activate
              pip install -q -r tools/requirements.txt
              python3 tools/precheck.py \
                --rules-dir detections/rules \
                --exceptions-dir detections/exceptions \
                --schema detections/schemas/rule.schema.json \
                --lockfile detections/rules.lock.json
            '''
          }
        }

        stage('Lockfile integrity') {
          steps {
            // precheck rewrites the lockfile only with --update-lock; if the
            // committed file is stale, the working tree is dirty -> fail.
            sh '''
              git diff --exit-code rules.lock.json || {
                echo "rules.lock.json is out of date. Run:"
                echo "  python3 tools/precheck.py --update-lock"
                echo "and commit the result in the same PR."
                exit 1
              }
            '''
          }
        }

        stage('Terraform lint') {
          steps {
            sh '''
              terraform -chdir=${TF_DIR} fmt -check -recursive -diff
              terraform -chdir=terraform/modules/detections fmt -check -diff
              tflint --recursive --minimum-failure-severity=warning || true
            '''
          }
        }
      }
    }

    // -------------------------------------------------------------------
    // Query validation against a throwaway/dev cluster. This is the only
    // way to catch a malformed EQL/ES|QL query before it hits production,
    // because the Terraform provider defers query validation to Kibana.
    // -------------------------------------------------------------------
    stage('Query dry-run (dev cluster)') {
      when { expression { env.DEV_KIBANA_URL != null } }
      steps {
        withCredentials([usernamePassword(credentialsId: 'elastic-dev-kibana',
                                          usernameVariable: 'DEV_KIBANA_USERNAME',
                                          passwordVariable: 'DEV_KIBANA_PASSWORD')]) {
          sh '''
            . .venv/bin/activate
            terraform -chdir=${TF_DIR} init -reconfigure -backend-config=backends/dev.hcl
            terraform -chdir=${TF_DIR} apply -auto-approve -var-file=targets/dev.tfvars
            python3 tools/postcheck.py --cluster dev --settle 60
          '''
        }
      }
    }

    // -------------------------------------------------------------------
    // PLAN both clusters in parallel, guard the blast radius
    // -------------------------------------------------------------------
    stage('Plan') {
      parallel {
        stage('Plan DC') { steps { script { tfPlan('dc') } } }
        stage('Plan DR') {
          when { expression { !params.SKIP_DR } }
          steps { script { tfPlan('dr') } }
        }
      }
    }

    stage('Approval') {
      when {
        allOf {
          branch 'main'
          expression { !params.AUTO_APPROVE }
        }
      }
      steps {
        timeout(time: 30, unit: 'MINUTES') {
          input message: 'Apply detection rules to DC and DR?',
                ok: 'Apply',
                submitter: 'soc-leads,detection-engineering'
        }
      }
    }

    // -------------------------------------------------------------------
    // APPLY: DC first. DR only proceeds if DC's post-check passed.
    // -------------------------------------------------------------------
    stage('Apply DC') {
      when { branch 'main' }
      steps { script { tfApply('dc') } }
    }

    stage('Post-check DC') {
      when { branch 'main' }
      steps { script { postCheck('dc', 120) } }
    }

    stage('Apply DR') {
      when {
        allOf { branch 'main'; expression { !params.SKIP_DR } }
      }
      steps { script { tfApply('dr') } }
    }

    stage('Post-check DR') {
      when {
        allOf { branch 'main'; expression { !params.SKIP_DR } }
      }
      steps { script { postCheck('dr', 120) } }
    }

    // -------------------------------------------------------------------
    // The check that actually proves DC/DR sync
    // -------------------------------------------------------------------
    stage('DC/DR parity') {
      when {
        allOf { branch 'main'; expression { !params.SKIP_DR } }
      }
      steps {
        withCredentials([
          usernamePassword(credentialsId: 'elastic-dc-kibana', usernameVariable: 'DC_KIBANA_USERNAME', passwordVariable: 'DC_KIBANA_PASSWORD'),
          usernamePassword(credentialsId: 'elastic-dr-kibana', usernameVariable: 'DR_KIBANA_USERNAME', passwordVariable: 'DR_KIBANA_PASSWORD')
        ]) {
          sh '''
            . .venv/bin/activate
            export DC_KIBANA_URL="https://kibana-dc.internal.example.com:5601"
            export DR_KIBANA_URL="https://kibana-dr.internal.example.com:5601"
            python3 tools/drift_compare.py --left dc --right dr --show-diff
          '''
        }
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'plan-*.json, plan-*.txt, rules.lock.json',
                       allowEmptyArchive: true
      sh 'rm -rf .venv'
    }
    failure {
      // If DC applied but DR failed, the clusters are out of sync. Say so loudly.
      slackSend channel: '#soc-detections', color: 'danger',
        message: "DaC pipeline FAILED: ${env.JOB_NAME} #${env.BUILD_NUMBER}\n" +
                 "If this failed after 'Apply DC', DC and DR are DIVERGED. " +
                 "Re-run with SKIP_DR=false once DR is reachable.\n${env.BUILD_URL}"
    }
    success {
      slackSend channel: '#soc-detections', color: 'good',
        message: "DaC deployed to DC${params.SKIP_DR ? '' : ' and DR'} - " +
                 "${env.JOB_NAME} #${env.BUILD_NUMBER}"
    }
  }
}

// =============================================================================
// Helpers
// =============================================================================

def tfPlan(String cluster) {
  withCredentials([usernamePassword(credentialsId: "elastic-${cluster}-kibana",
                                    usernameVariable: 'KIBANA_USERNAME',
                                    passwordVariable: 'KIBANA_PASSWORD')]) {
    sh """
      set -e
      . .venv/bin/activate
      terraform -chdir=${TF_DIR} init -reconfigure -backend-config=backends/${cluster}.hcl
      terraform -chdir=${TF_DIR} validate
      terraform -chdir=${TF_DIR} plan \
        -lock-timeout=5m \
        -var-file=targets/${cluster}.tfvars \
        -out=${cluster}.tfplan
      terraform -chdir=${TF_DIR} show -json ${cluster}.tfplan > plan-${cluster}.json
      terraform -chdir=${TF_DIR} show -no-color ${cluster}.tfplan > plan-${cluster}.txt
      python3 tools/plan_guard.py plan-${cluster}.json \
        --max-destroy ${params.MAX_DESTROY} \
        --max-replace ${params.MAX_DESTROY}
    """
  }
}

def tfApply(String cluster) {
  withCredentials([usernamePassword(credentialsId: "elastic-${cluster}-kibana",
                                    usernameVariable: 'KIBANA_USERNAME',
                                    passwordVariable: 'KIBANA_PASSWORD')]) {
    sh """
      set -e
      terraform -chdir=${TF_DIR} init -reconfigure -backend-config=backends/${cluster}.hcl
      terraform -chdir=${TF_DIR} apply -lock-timeout=5m -auto-approve ${cluster}.tfplan
      terraform -chdir=${TF_DIR} output -json rule_index > rule-index-${cluster}.json
    """
  }
}

def postCheck(String cluster, int settle) {
  def upper = cluster.toUpperCase()
  withCredentials([usernamePassword(credentialsId: "elastic-${cluster}-kibana",
                                    usernameVariable: "${upper}_KIBANA_USERNAME",
                                    passwordVariable: "${upper}_KIBANA_PASSWORD")]) {
    sh """
      . .venv/bin/activate
      export ${upper}_KIBANA_URL="https://kibana-${cluster}.internal.example.com:5601"
      python3 tools/postcheck.py --cluster ${cluster} --settle ${settle}
    """
  }
}
