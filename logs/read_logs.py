import win32evtlog

server = "localhost"
log_type = "Security"

handle = win32evtlog.OpenEventLog(server, log_type)

flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

print("🔐 Real-Time Security Monitoring Started...\n")

# 🎯 Important events
important_events = {
    4624: "Login Success",
    4625: "Failed Login 🚨",
    4634: "Logoff",
    4648: "Explicit Credential Logon ⚠️",
    4720: "User Account Created 🚨",
    4722: "Account Enabled",
    4723: "Password Change Attempt",
    4726: "Account Deleted",
    4672: "Admin Privileges Assigned 🚨",
    4688: "Process Created ⚠️",
    5156: "Network Connection Allowed",
    5157: "Connection Blocked 🚨",
    6005: "System Startup",
    6006: "System Shutdown"
}

while True:
    events = win32evtlog.ReadEventLog(handle, flags, 0)

    if events:
        for event in events:

            event_id = event.EventID

            if event_id in important_events:

                event_type = important_events[event_id]

                print("🚨 IMPORTANT EVENT DETECTED")
                print("Event ID:", event_id)
                print("Type:", event_type)
                print("Source:", event.SourceName)
                print("Time:", event.TimeGenerated)

                # 🔥 Risk Level
                if "🚨" in event_type:
                    print("Risk Level: HIGH")
                elif "⚠️" in event_type:
                    print("Risk Level: MEDIUM")
                else:
                    print("Risk Level: LOW")

                print("-" * 60)