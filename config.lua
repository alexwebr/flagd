-- This is a list of the team names
teams =  {
  "Nikogiri",
  "Supermen",
  "Hon-Hai Connection",
  "Taking a Wikileak",
}

-- This is the listing of the secret keys that the teams are supposed to find
keys = {
  { val = "ec92c924b9a76327ac53fb8668d7398c", desc="Got Administrator on Win2k3 server" },
  { val = "480748d06d43885b2ad22dd3812db154", desc="Exploited MySQL" },
  { val = "480748d06d43885b2ad22dd3812db154", desc="Recovered files from fubar filesystem" },
}

-- The port to bind to
port = 9001
-- The file to log to
capture_log = "capture.log"
admin_log = "admin.log"
-- The IP address to bind to. '*' binds to all addresses
ip_address = "*"
-- The number of seconds an IP will be prevented from attempting to submit a key.
submission_delay = 5
-- Display key descriptions? Sometimes descriptions can give hints to other teams.
show_key_info = true
