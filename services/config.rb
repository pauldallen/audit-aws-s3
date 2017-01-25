###########################################
# User Visible Rule Definitions
###########################################

coreo_aws_advisor_alert "s3-allusers-write" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-allusers-write.html"
  display_name "All users can write to the affected bucket"
  description "Bucket has permissions (ACL) which let all users write to the bucket."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to write."
  level "Critical"
  objectives    ["bucket_acl","bucket_acl","bucket_location"]
  audit_objects ["grants.grantee.uri", "grants.permission", "location_constraint"]
  operators     ["=~", "==", "=~"]
  alert_when    [/AllUsers/i, "write", //]
  id_map "modifiers.bucket_name"
end

coreo_aws_advisor_alert "s3-allusers-write-acp" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-allusers-write-acp.html"
  display_name "All users can write the bucket ACP / ACL"
  description "Bucket has permissions (ACP / ACL) which let all users modify the permissions."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to edit permissions."
  level "Emergency"
  objectives    [ "bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=="]
  alert_when    [/AllUsers/i, "write_acp"]
  id_map "modifiers.bucket_name"
end

coreo_aws_advisor_alert "s3-allusers-read" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-allusers-read.html"
  display_name "All users can list the affected bucket"
  description "Bucket has permissions (ACL) which let anyone list the bucket contents."
  category "Security"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to list the bucket."
  level "Critical"
  objectives    [ "bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=="]
  alert_when    [/AllUsers/i, "read"]
  id_map "modifiers.bucket_name"
end

coreo_aws_advisor_alert "s3-authenticatedusers-write" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-authenticatedusers-write.html"
  display_name "All authenticated AWS users can write to the affected bucket"
  description "Bucket has permissions (ACL) which let any AWS users write to the bucket."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows 'Any Authenticated AWS User' to write."
  level "Critical"
  objectives    [ "bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=="]
  alert_when    [/AuthenticatedUsers/i, "write"]
  id_map "modifiers.bucket_name"
end

coreo_aws_advisor_alert "s3-authenticatedusers-write-acp" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-authenticatedusers-write-acp.html"
  display_name "All authenticated AWS users can change bucket permissions"
  description "Bucket has permissions ( ACP / ACL) which let any AWS user modify the permissions."
  category "Dataloss"
  suggested_action "Remove the bucket permissions (ACP / ACL) that allows 'Any Authenticated AWS User' to edit permissions."
  level "Danger"
  objectives    [ "bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=="]
  alert_when    [/AuthenticatedUsers/i, "write_acp"]
  id_map "modifiers.bucket_name"
end

coreo_aws_advisor_alert "s3-authenticatedusers-read" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-authenticatedusers-read.html"
  display_name "All authenticated AWS users can read the affected bucket"
  description "Bucket has permissions (ACL) which let any AWS user list the bucket contents."
  category "Security"
  suggested_action "Remove the entry from the bucket permissions that allows 'Any Authenticated AWS User' to list the bucket."
  level "Critical"
  objectives    [ "bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=="]
  alert_when    [/AuthenticatedUsers/i, "read"]
  id_map "modifiers.bucket_name"
end

coreo_aws_advisor_alert "s3-logging-disabled" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-logging-disabled.html"
  display_name "S3 bucket logging not enabled"
  description "S3 bucket logging has not been enabled for the affected resource."
  category "Audit"
  suggested_action "Enable logging on your S3 buckets."
  level "Warning"
  objectives    ["bucket_logging"]
  audit_objects [""]
  operators     ["=="]
  alert_when    [nil]
  id_map "modifiers.bucket_name"
end

coreo_aws_advisor_alert "s3-world-open-policy-delete" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-world-open-policy-delete.html"
  display_name "Bucket policy gives world delete permission"
  description "Bucket policy allows the world to delete the affected bucket and/or its contents"
  category "Dataloss"
  suggested_action "Remove or modify the bucket policy that enables the world to delete the contents of this bucket or even the bucket itself."
  level "Emergency"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[?Effect == 'Allow' && Principal == '*' && !Condition]"]
  operators     ["=~"]
  alert_when    [/s3:Delete*/]
  id_map "modifiers.bucket_name"
end

coreo_aws_advisor_alert "s3-world-open-policy-get" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-world-open-policy-get.html"
  display_name "Bucket policy gives world Get permission"
  description "Bucket policy allows the world to get the contents of the affected bucket."
  category "Security"
  suggested_action "Remove or modify the bucket policy that enables the world to get the contents of this bucket."
  level "Critical"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[?Effect == 'Allow' && Principal == '*' && !Condition]"]
  operators     ["=~"]
  alert_when    [/s3:Get*/]
  id_map "modifiers.bucket_name"
end

coreo_aws_advisor_alert "s3-world-open-policy-list" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-world-open-policy-list.html"
  display_name "Bucket policy gives world List permission"
  description "Bucket policy allows the world to list the contents of the affected bucket"
  category "Security"
  suggested_action "Remove or modify the bucket policy that enables the world to list the contents of this bucket."
  level "Danger"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[?Effect == 'Allow' && Principal == '*' && !Condition]"]
  operators     ["=~"]
  alert_when    [/s3:List*/]
  id_map "modifiers.bucket_name"
end

coreo_aws_advisor_alert "s3-world-open-policy-put" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-world-open-policy-put.html"
  display_name "Bucket policy gives world Put permission"
  description "Bucket policy allows the world to put data into the affected bucket."
  category "Dataloss"
  suggested_action "Remove the bucket permission that enables the world to put (and overwrite) data in this bucket."
  level "Danger"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[?Effect == 'Allow' && Principal == '*' && !Condition]"]
  operators     ["=~"]
  alert_when    [/s3:Put*/]
  id_map "modifiers.bucket_name"
end

coreo_aws_advisor_alert "s3-world-open-policy-all" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-world-open-policy-all.html"
  display_name "Bucket policy gives the world permission to do anything in the bucket"
  description "Bucket policy gives the world permission to do anything in the bucket"
  category "Dataloss"
  suggested_action "Modify the principle to remove the * notation which signifies any person or remove the * from allowed actions which signifies allowing any possible action on the bucket or its contents."
  level "Emergency"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[?Effect == 'Allow' && Action == 's3:*' && Principal == '*' && !Condition]"]
  operators     ["=~"]
  alert_when    [/[^\[\]\{\}]/]
  id_map "modifiers.bucket_name"
end

coreo_aws_advisor_alert "s3-only-ip-based-policy" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-only-ip-based-policy.html"
  display_name "Bucket policy uses IP addresses to grant permission"
  description "Bucket policy grants permissions to any user at an IP address or range to perform operations on objects in the specified bucket."
  category "Security"
  suggested_action "Consider using other methods to grant permission to perform operations on your S3 buckets."
  level "Critical"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[*].[Effect, Condition]"]
  operators     ["=~"]
  alert_when    [/"(Allow|Deny)",[^{]*({"IpAddress")[^}]*}}\]/]
  id_map "modifiers.bucket_name"
end

###########################################
# Compsite-Internal Resources follow until end
#   (Resources used by the system for execution and display processing)
###########################################

coreo_aws_advisor_s3 "advise-s3" do
  action :advise
  alerts ${AUDIT_AWS_S3_ALERT_LIST}
#  regions ${AUDIT_AWS_S3_REGIONS}  
  global_objective "buckets"
  bucket_name /.*/
  global_modifier({:bucket_name => "buckets.name"})
end

=begin
  START AWS S3 METHODS
  JSON SEND METHOD
  HTML SEND METHOD
=end

coreo_uni_util_jsrunner "jsrunner-process-suppression-s3" do
  action :run
  provide_composite_access true
  json_input '{"violations":COMPOSITE::coreo_aws_advisor_s3.advise-s3.report}'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
  var fs = require('fs');
  var yaml = require('js-yaml');
  let suppression;
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
  }
  coreoExport('suppression', JSON.stringify(suppression));
  var violations = json_input.violations;
  var result = {};
    var file_date = null;
    for (var violator_id in violations) {
        result[violator_id] = {};
        result[violator_id].tags = violations[violator_id].tags;
        result[violator_id].violations = {}
        for (var rule_id in violations[violator_id].violations) {
            is_violation = true;
 
            result[violator_id].violations[rule_id] = violations[violator_id].violations[rule_id];
            for (var suppress_rule_id in suppression) {
                for (var suppress_violator_num in suppression[suppress_rule_id]) {
                    for (var suppress_violator_id in suppression[suppress_rule_id][suppress_violator_num]) {
                        file_date = null;
                        var suppress_obj_id_time = suppression[suppress_rule_id][suppress_violator_num][suppress_violator_id];
                        if (rule_id === suppress_rule_id) {
 
                            if (violator_id === suppress_violator_id) {
                                var now_date = new Date();
 
                                if (suppress_obj_id_time === "") {
                                    suppress_obj_id_time = new Date();
                                } else {
                                    file_date = suppress_obj_id_time;
                                    suppress_obj_id_time = file_date;
                                }
                                var rule_date = new Date(suppress_obj_id_time);
                                if (isNaN(rule_date.getTime())) {
                                    rule_date = new Date(0);
                                }
 
                                if (now_date <= rule_date) {
 
                                    is_violation = false;
 
                                    result[violator_id].violations[rule_id]["suppressed"] = true;
                                    if (file_date != null) {
                                        result[violator_id].violations[rule_id]["suppressed_until"] = file_date;
                                        result[violator_id].violations[rule_id]["suppression_expired"] = false;
                                    }
                                }
                            }
                        }
                    }
 
                }
            }
            if (is_violation) {
 
                if (file_date !== null) {
                    result[violator_id].violations[rule_id]["suppressed_until"] = file_date;
                    result[violator_id].violations[rule_id]["suppression_expired"] = true;
                } else {
                    result[violator_id].violations[rule_id]["suppression_expired"] = false;
                }
                result[violator_id].violations[rule_id]["suppressed"] = false;
            }
        }
    }
 
    var rtn = result;
  
  var rtn = result;
  
  callback(result);
  EOH
end

coreo_uni_util_jsrunner "jsrunner-process-table-s3" do
  action :run
  provide_composite_access true
  json_input '{"violations":COMPOSITE::coreo_aws_advisor_s3.advise-s3.report}'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
    var fs = require('fs');
    var yaml = require('js-yaml');
    try {
        var table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
    } catch (e) {
    }
    coreoExport('table', JSON.stringify(table));
    callback(table);
  EOH
end

coreo_uni_util_notify "advise-s3-json" do
  action :nothing
  type 'email'
  allow_empty ${AUDIT_AWS_S3_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_S3_SEND_ON}'
  payload '{"composite name":"PLAN::stack_name",
  "plan name":"PLAN::name",
  "number_of_checks":"COMPOSITE::coreo_aws_advisor_s3.advise-s3.number_checks",
  "number_of_violations":"COMPOSITE::coreo_aws_advisor_s3.advise-s3.number_violations",
  "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_s3.advise-s3.number_ignored_violations",
  "violations": COMPOSITE::coreo_aws_advisor_s3.advise-s3.report }'
  payload_type "json"
  endpoint ({
      :to => '${AUDIT_AWS_S3_ALERT_RECIPIENT}', :subject => 'CloudCoreo s3 advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-s3" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.6.0"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "table": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-table-s3.return,
                "violations": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppression-s3.return}'
  function <<-EOH
 
const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_S3_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_S3_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_S3_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_S3_SEND_ON}";
const AUDIT_NAME = 's3';
const TABLES = json_input['table'];
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;

const WHAT_NEED_TO_SHOWN_ON_TABLE = {
    OBJECT_ID: { headerName: 'AWS Object ID', isShown: true},
    REGION: { headerName: 'Region', isShown: true },
    AWS_CONSOLE: { headerName: 'AWS Console', isShown: true },
    TAGS: { headerName: 'Tags', isShown: true },
    AMI: { headerName: 'AMI', isShown: false },
    KILL_SCRIPTS: { headerName: 'Kill Cmd', isShown: false }
};

const VARIABLES = { NO_OWNER_EMAIL, OWNER_TAG, AUDIT_NAME,
    WHAT_NEED_TO_SHOWN_ON_TABLE, ALLOW_EMPTY, SEND_ON,
    undefined, undefined, SHOWN_NOT_SORTED_VIOLATIONS_COUNTER};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditS3 = new CloudCoreoJSRunner(JSON_INPUT, VARIABLES, TABLES);
const notifiers = AuditS3.getNotifiers();
callback(notifiers);
  EOH
end


coreo_uni_util_notify "advise-s3-to-tag-values" do
  action :${AUDIT_AWS_S3_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.return'
end

coreo_uni_util_jsrunner "tags-rollup-s3" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.return'
  function <<-EOH
var rollup_string = "";
let rollup = '';
let emailText = '';
let numberOfViolations = 0;
for (var entry=0; entry < json_input.length; entry++) {
    if (json_input[entry]['endpoint']['to'].length) {
        numberOfViolations += parseInt(json_input[entry]['num_violations']);
        emailText += "recipient: " + json_input[entry]['endpoint']['to'] + " - " + "Violations: " + json_input[entry]['num_violations'] + "\\n";
    }
}

rollup += 'number of Violations: ' + numberOfViolations + "\\n";
rollup += 'Rollup' + "\\n";
rollup += emailText;

rollup_string = rollup;
callback(rollup_string);
  EOH
end


coreo_uni_util_notify "advise-s3-rollup" do
  action :${AUDIT_AWS_S3_ROLLUP_REPORT}
  type 'email'
  allow_empty ${AUDIT_AWS_S3_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_S3_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup-s3.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_S3_ALERT_RECIPIENT}', :subject => 'CloudCoreo s3 advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end
=begin
  AWS S3 END
=end
