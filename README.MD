# Bose Audio Messages - A Demo
Tap and hold a product to record and send a quick audio message to a Bose Smart speaker or soundbar. Containerized flask app deployed on AWS ECS.

### TODO
Loosely in priority order below
- ~Fix audio quality issue (rtr)~ done!
- ~Add in login/persistence (rtr)~ done!
- ~update repo to use `main` instead of `master` (guide https://www.hanselman.com/blog/EasilyRenameYourGitDefaultBranchFromMasterToMain.aspx) (also don't forget to update the aws deployment action config file)~
- ~consider fixes for early cutoff issue (rtr)~
- ~remove Bose branding (zwr)~ done!
- ~Add styling for login pages (zwr)~
- ~Add external provider sign-in options for BAM accounts (zwr)~
  - ~Google~ ~(needs updating to client-side)~
  - ~Facebook~
- consider redesign of primary page to get more products on screen without scrolling on typical phone sizes (zwr)
- [Pending UX resolution] Add support for all product images plus default (zwr)
- add loading spinners for social login buttons
- add tests (zwr)
- genericize to include Sonos
- improve error handling (zwr)
- ~add volume override support (zwr)~
- make this README better
