linear-slack-notifier
=====================

Posts Linear issue events to Slack without their content.

Linear's built-in Slack notifications include issue titles, descriptions and
comments. For support tickets those contain customer data. This service
receives Linear's issue webhooks instead and posts only the identifier and
what happened:

    SUP-123 created
    SUP-123 → Done

The identifier links to the issue, with Slack link previews disabled.

Configuration
-------------

| Variable                | Required | Description                                                |
|-------------------------|----------|------------------------------------------------------------|
| `LINEAR_WEBHOOK_SECRET` | yes      | Signing secret of the Linear webhook                       |
| `SLACK_WEBHOOK_URL`     | yes      | Slack incoming webhook URL of the channel to post to       |
| `LINEAR_TEAM_KEY`       | no       | Only post issues of this team, e.g. `SUP`                  |
| `LISTEN_ADDR`           | no       | Address to listen on, default `:8080`                      |

The service listens on `POST /webhook` and has a health check on `GET /healthz`.

Setup
-----

1. In Slack, add an incoming webhook for the channel to post to (a Slack app
   with *Incoming Webhooks* enabled) and use its URL as `SLACK_WEBHOOK_URL`.
2. In Linear, go to *Settings → Administration → API* and create a webhook
   with URL `https://<host>/webhook`, the Support team, and only *Issues* as
   data change event. Use its signing secret as `LINEAR_WEBHOOK_SECRET`.
3. Turn off the team's own Slack notifications in Linear (*Team settings →
   Slack notifications*), otherwise the full content is still posted.

Privacy
-------

* Only the identifier, team, status and URL are decoded from the webhook; the
  title, description and other content are ignored and never logged.
* Links to issues in a **public** Linear team can still be expanded by Linear's
  own Slack app, and Linear replies to issue IDs mentioned in Slack with a
  link. Making the team private prevents both; otherwise disable unfurls and
  issue ID replies in Linear under *Settings → Integrations → Slack*.

Development
-----------

    go test ./...
    docker build -t linear-slack-notifier .
