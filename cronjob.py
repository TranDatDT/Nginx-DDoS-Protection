# Run it for the first time

from crontab import CronTab

cron = CronTab()
job = cron.new(command='python3 /home/trandatdt/PycharmProjects/ddos-protection-v7/main.py')
job.minute.every(1)

cron.write()
