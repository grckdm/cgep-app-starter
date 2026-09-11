# terraform/gap08_apigw_override.tf
#
# GAP-08 — SOC 2 CC7.2. Adds access logging (to the log group + resource
# policy defined in hardening.tf) and per-route throttling to the
# $default stage. Values are conservative starting points for a low-
# volume intake API — revisit under real load testing.
resource "aws_apigatewayv2_stage" "default" {
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw_access.arn
    format = jsonencode({
      requestId       = "$context.requestId"
      ip              = "$context.identity.sourceIp"
      requestTime     = "$context.requestTime"
      httpMethod      = "$context.httpMethod"
      routeKey        = "$context.routeKey"
      status          = "$context.status"
      integrationErr  = "$context.integrationErrorMessage"
      responseLatency = "$context.responseLatency"
    })
  }

  default_route_settings {
    throttling_burst_limit   = 20
    throttling_rate_limit    = 10
    detailed_metrics_enabled = true
  }
}
