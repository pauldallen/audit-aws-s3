
coreo_aws_advisor_alert "s3-allusers-write" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-allusers-write.html"
  display_name "All users can write to the affected bucket"
  description "Bucket has permissions (ACL) which let all users write to the bucket."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to write."
  level "Critical"
  objectives    ["bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=="]
  alert_when    [/AllUsers/i, "write"]
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
end

coreo_aws_advisor_alert "s3-allusers-read" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-allusers-read.html"
  display_name "All users can list the affected bucket"
  description "Bucket has permissions (ACL) which let anyone list the bucket contents."
  category "Security"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to list the bucket."
  level "Alert"
  objectives    [ "bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=="]
  alert_when    [/AllUsers/i, "read"]
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
end

coreo_aws_advisor_alert "s3-authenticatedusers-write-acp" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-authenticatedusers-write-acp.html"
  display_name "All authenticated AWS users can change bucket permissions"
  description "Bucket has permissions ( ACP / ACL) which let any AWS user modify the permissions."
  category "dataloss"
  suggested_action "Remove the bucket permissions (ACP / ACL) that allows 'Any Authenticated AWS User' to edit permissions."
  level "danger"
  objectives    [ "bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=="]
  alert_when    [/AuthenticatedUsers/i, "write_acp"]
end

coreo_aws_advisor_alert "s3-authenticatedusers-read" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-authenticatedusers-read.html"
  display_name "All authenticated AWS users can read the affected bucket"
  description "Bucket has permissions (ACL) which let any AWS user list the bucket contents."
  category "Security"
  suggested_action "Remove the entry from the bucket permissions that allows 'Any Authenticated AWS User' to list the bucket."
  level "Alert"
  objectives    [ "bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=="]
  alert_when    [/AuthenticatedUsers/i, "read"]
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
end

coreo_aws_advisor_alert "s3-world-open-policy-list" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-world-open-policy-list.html"
  display_name "Bucket policy gives world List permission"
  description "Bucket policy allows the world to list the contents of the affected bucket"
  category "Security"
  suggested_action "Remove or modify the bucket policy that enables the world to list the contents of this bucket."
  level "danger"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[?Effect == 'Allow' && Principal == '*' && !Condition]"]
  operators     ["=~"]
  alert_when    [/s3:List*/]
end

coreo_aws_advisor_alert "s3-world-open-policy-put" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-world-open-policy-put.html"
  display_name "Bucket policy gives world Put permission"
  description "Bucket policy allows the world to put data into the affected bucket."
  category "Dataloss"
  suggested_action "Remove the bucket permission that enables the world to put (and overwrite) data in this bucket."
  level "danger"
  objectives    ["bucket_policy"]
  audit_objects ["policy"]
  formulas      ["jmespath.Statement[?Effect == 'Allow' && Principal == '*' && !Condition]"]
  operators     ["=~"]
  alert_when    [/s3:Put*/]
end

# note we changed the regex and metadata on this rule so the KB link will need to be re-validated (that is why its commented out)
#
coreo_aws_advisor_alert "s3-world-open-policy-all" do
  action :define
  service :s3
  #link "http://kb.cloudcoreo.com/mydoc_s3-world-open-policy-all.html"
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
end

coreo_aws_advisor_s3 "advise-s3" do
  action :advise
  alerts ${AUDIT_AWS_S3_ALERT_LIST}
  regions ${AUDIT_AWS_S3_REGIONS}  
  global_objective "buckets"
  bucket_name /.*/
  global_modifier({:bucket_name => "buckets.name"})
end

=begin
  START AWS S3 METHODS
  JSON SEND METHOD
  HTML SEND METHOD
=end
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
                   :version => "1.2.1"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "number_of_checks":"COMPOSITE::coreo_aws_advisor_s3.advise-s3.number_checks",
                "number_of_violations":"COMPOSITE::coreo_aws_advisor_s3.advise-s3.number_violations",
                "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_s3.advise-s3.number_ignored_violations",
                "violations": COMPOSITE::coreo_aws_advisor_s3.advise-s3.report}'
  function <<-EOH
 
const JSON = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_S3_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_S3_OWNER_TAG}";
const AUDIT_NAME = 's3';
const ARE_KILL_SCRIPTS_SHOWN = false;
const EC2_LOGIC = ''; // you can choose 'and' or 'or';
const EXPECTED_TAGS = [];
const WHAT_NEED_TO_SHOWN = {
    OBJECT_ID: {
        headerName: 'AWS Object ID',
        isShown: true,
    },
    REGION: {
        headerName: 'Region',
        isShown: true,
    },
    AWS_CONSOLE: {
        headerName: 'AWS Console',
        isShown: true,
    },
    TAGS: {
        headerName: 'Tags',
        isShown: true,
    },
    AMI: {
        headerName: 'AMI',
        isShown: false,
    },
    KILL_SCRIPTS: {
        headerName: 'Kill Cmd',
        isShown: false,
    }
};


const VARIABLES = {
    NO_OWNER_EMAIL,
    OWNER_TAG,
    AUDIT_NAME,
    ARE_KILL_SCRIPTS_SHOWN,
    EC2_LOGIC,
    EXPECTED_TAGS,
    WHAT_NEED_TO_SHOWN
};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditS3 = new CloudCoreoJSRunner(JSON, VARIABLES);
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
for (var entry=0; entry < json_input.length; entry++) {
  console.log(json_input[entry]);
  if (json_input[entry]['endpoint']['to'].length) {
    console.log('got an email to rollup');
    rollup_string = rollup_string + "recipient: " + json_input[entry]['endpoint']['to'] + " - " + "nViolations: " + json_input[entry]['num_violations'] + "\\n";
  }
}
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
number_of_checks: COMPOSITE::coreo_aws_advisor_s3.advise-s3.number_checks
number_of_violations: COMPOSITE::coreo_aws_advisor_s3.advise-s3.number_violations
number_violations_ignored: COMPOSITE::coreo_aws_advisor_s3.advise-s3.number_ignored_violations

rollup report:
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
