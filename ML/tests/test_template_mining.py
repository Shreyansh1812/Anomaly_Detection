from ML.modules.template_mining import LogTemplateMiner

# Sample log messages
messages = [
    "2025-09-16 10:00:01 INFO User admin logged in from 192.168.1.10",
    "2025-09-16 10:01:02 ERROR Failed password for user root from 10.0.0.5",
    "2025-09-16 10:02:03 WARN Disk quota exceeded for user alice",
    "2025-09-16 10:03:04 INFO User bob logged out"
]

miner = LogTemplateMiner()
df = miner.extract_templates(messages)
print(df)
