-- This is a list of the team names
teams =  {
  { name = "Nikogiri", pass = "superpass" },
  { name = "Supermen", pass = "hunter2" },
  { name = "Hon-Hai Connection", pass = "$blitz12" },
  { name = "Taking a Wikileak", pass = "%%he11083?w0rld" },
}

-- This is the listing of the secret flags that the teams are supposed to find
flags = {
  { sec = "ec92c924b9a76327ac53fb8668d7398c", desc="Got Administrator on Win2k3 server" },
  { sec = "480748d06d43885b2ad22dd3812db154", desc="Exploited MySQL" },
  { sec = "19df03ce49121abc7d351e0ac8e4cd4f", desc="Recovered files from fubar filesystem" },
}

-- The port to bind to
port = 9001
-- The file to log to
capture_log = "capture.log"
admin_log = "admin.log"
-- The IP address to bind to. '*' binds to all addresses
ip_address = "*"
-- The number of seconds an IP will be prevented from attempting to submit a flag.
submission_delay = 5
-- Show a flag's description in the capture log? Sometimes descriptions can give hints to other teams.
-- If you wish to only hide descriptions for certain flags, simply leave a flag without a description
show_flag_descriptions = true
