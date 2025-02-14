#include <core.p4>
#include <tna.p4>
#include "includes/parser_a.p4"
#include "includes/parser_b.p4"
#include "includes/deparser_a.p4"
#include "includes/deparser_b.p4"
#include "pipeline_profile_a.p4"
#include "pipeline_profile_b.p4"

// Packet comes into ingress profile_a, then travels to egress profile_b, then to ingress profile_b and finally to egress profile_a.

Pipeline(SwitchIngressParser_a(),
         SwitchIngress_a(),
         SwitchIngressDeparser_a(),
         SwitchEgressParser_a(),
         SwitchEgress_a(),
         SwitchEgressDeparser_a()) pipeline_profile_a;

Pipeline(SwitchIngressParser_b(),
         SwitchIngress_b(),
         SwitchIngressDeparser_b(),
         SwitchEgressParser_b(),
         SwitchEgress_b(),
         SwitchEgressDeparser_b()) pipeline_profile_b;

Switch(pipeline_profile_a, pipeline_profile_b) main;
