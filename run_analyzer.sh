#!/bin/bash

LOG_DIR="/home/$(whoami)/Documents/log_analyzer" #log analyzer directory
cd $LOG_DIR # Change to the log analyzer directory

sudo python3 log_analyzer.py >> /var/log/analyzer_runs.log 2>&1

TIMESTAMP=$(date +"%Y%m%d_%H%M%S") # Generate a timestamp for the report filename
sudo cp report.html /var/www/html/report.html # Copy the report to the web server directory with a timestamped filename
sudo cp report.html /var/www/html/report_$TIMESTAMP.html # Copy, with a timestamped filename

echo "$(date): Analyzer run complete" >> /var/log/analyzer_runs.log # Log the completion of the analyzer run