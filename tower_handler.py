#!/usr/bin/python
#
# Copyright 2018 Red Hat, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# This script has been designed to be run as a
# Nagios Service Handler. It will trigger an
# Ansible Tower job template.
#
# Web site: https://github.com/ansible/tower-nagios-integration
# Author: https://github.com/badnetmask

import os
import sys
import json
import syslog
import argparse
import requests

# things we pass to the job POST call
job_data = {}
# prevents log_run from breaking
job_number=""
job_status=""
# used to find by name
template_number=None
inventory_number=None

parser = argparse.ArgumentParser()
#parser.add_argument("-H", "--host", help="Tower host", required=True)
#parser.add_argument("-u", "--username", help="Tower username", required=True)
#parser.add_argument("-p", "--password", help="Tower password", required=True)
parser.add_argument("--template", help="Job template (number or name)", required=True)
parser.add_argument("--inventory", help="Inventory (number or name)", required=True)
parser.add_argument("--playbook", help="Playbook to run (yaml file inside template)", required=False)
parser.add_argument("--extra_vars", help="Extra variables (JSON)", required=False)
parser.add_argument("--limit", help="Limit run to these hosts (group name, or comma separated hosts)", required=False)
parser.add_argument("--state", help="Nagios check state", required=False)
parser.add_argument("--attempt", help="Nagios check attempt", required=False, type=int)
parser.add_argument("--downtime", help="Nagios service downtime check", required=False, type=int)
parser.add_argument("--host_downtime", help="Nagios host downtime check", required=False, type=int)
parser.add_argument("--service", help="Nagios alerting service", required=False)
parser.add_argument("--hostname", help="Nagios alerting hostname", required=False)
parser.add_argument("--warning", help="Trigger on WARNING (otherwise just CRITICAL and UNKNOWN)", required=False, action='store_true')

args = parser.parse_args()

tower_host = os.getenv('TOWER_HOST')
tower_username = os.getenv('TOWER_USERNAME')
tower_password = os.getenv('TOWER_PASSWORD')

if not (tower_host and tower_username and tower_password):
  print("Error: missing host or authentication information.")
  sys.exit(1)

awxsession = requests.Session()
# initiate the conversation with Tower to get a token
csrftoken = awxsession.get(tower_host + '/api/').cookies['csrftoken']
awxsession_data = {
  'username': tower_username,
  'password': tower_password,
  'next': '/api/'
}
awxsession_headers = {
  'Content-Type': 'application/x-www-form-urlencoded',
  'Referer': tower_host + '/api/login/',
  'X-CSRFToken': csrftoken,
}
# attempt to login to Tower
r = awxsession.post(tower_host + '/api/login/',
  headers=awxsession_headers, data=awxsession_data)
if not r.status_code == 200:
  print('Error authenticating against the Ansible Tower host.')
  sys.exit(1)

# from now on, we only deal with json data
# also, the token cookie was reset
awxsession_headers = {
  'Content-Type': 'application/json',
  'Referer': tower_host + '/api/login/',
  'X-CSRFToken': awxsession.cookies['csrftoken'],
}

def logger(msg):
    syslog.syslog(msg)

def error(msg):
  sys.stderr.write(msg + "\n")
  sys.exit(3)

def info(msg):
  print(msg)

def log_run(msg):
    # kind of NRPE-style logging
    logger('job_number=%s job_status="%s" service="%s" hostname="%s" service_state="%s" service_attempt=%s service_downtime=%s host_downtime=%s template="%s" inventory="%s" extra_vars="%s" limit="%s" handler_message="%s"' %
            (job_number, job_status, args.service, args.hostname, args.state, args.attempt, args.downtime, args.host_downtime, args.template, args.inventory, args.extra_vars, args.limit, msg))

def awxget(endpoint):
  return awxsession.get(tower_host + '/api/v2' + endpoint, headers=awxsession_headers)

def awxpost(endpoint, data):
  return awxsession.post(tower_host + '/api/v2' + endpoint, headers=awxsession_headers, data=json.dumps(data))

# proof that it works
# print(awxget('/config/').json()['version'])
# sys.exit(0)

if args.state == "OK" or \
  args.downtime > 0 or \
  args.host_downtime > 0 or \
  args.attempt <= 1 or \
  (args.state == "WARNING" and args.warning == False):
  # don't run handler if either one is true:
  # - service state is OK
  # - downtime is set
  # - this is the first attempt
  # - option --warning is not set
  log_run("SKIP: skipped")
  sys.exit(0)

if not args.template.isdigit():
  try:
    # when --template is a name, we need the number
    find_template = awxget('/job_templates/?name=%s' % args.template)
    template_number = find_template.json()['results'][0]['id']
  except exceptions.AuthError:
    log_run("Error authenticating to tower. Check user/password.")
    error("Error authenticating to tower. Check user/password.")
  except exceptions.NotFound:
    log_run("ERROR: template not found")
    error("The template %s could not be found." % args.template)
else:
  # when --template is a number
  template_number = args.template

try:
  job_check = awxget('/job_templates/%s' % template_number)
  #print json.dumps(job_check.json(), indent=2)
except exceptions.AuthError:
  log_run("Error authenticating to tower. Check user/password.")
  error("Error authenticating to tower. Check user/password.")
except exceptions.NotFound:
  log_run("ERROR: template not found")
  error("The template %s could not be found." % template_number)

if(job_check.json()['ask_inventory_on_launch'] and not args.inventory):
  log_run("ERROR: template requires inventory")
  error("This job template requires an inventory number.")

if not args.inventory.isdigit():
  try:
    # when --inventory is a name, we need a number
    find_inventory = awxget('/inventories/?name=%s' % args.inventory)
    inventory_number = find_inventory.json()['results'][0]['id']
  except exceptions.NotFound:
    log_run("ERROR: inventory not found")
    error("The inventory %s could not be found." % args.inventory)
else:
  # when --inventory is a number
  inventory_number = args.inventory

try:
  inventory_check = awxget('/inventories/%s' % inventory_number)
  job_data['inventory'] = inventory_number
except exceptions.NotFound:
  log_run("ERROR: inventory not found")
  error("The inventory %s could not be found." % inventory_number)

if(job_check.json()['ask_variables_on_launch']):
  if not args.state and not args.extra_vars:
    # probably means we are in interactive mode
    error("The job requires extra_vars in JSON format.")
  try:
    #json_extra_vars = json.loads(args.extra_vars)
    ## This value will help us filter for executed jobs in tower
    #json_extra_vars['nagios_handler'] = True
    #job_data['extra_vars'] = json_extra_vars
    # TODO: nagios is breaking quotes, so don't try to interpret JSON for now
    if args.extra_vars:
      job_data['extra_vars'] = args.extra_vars
    else:
      job_data['extra_vars'] = "{nagios_no_extra_var: true }"
  except ValueError:
    error("The extra_vars parameter is not valid JSON.")

if(job_check.json()['ask_limit_on_launch'] and not args.limit):
  log_run("ERROR: job requires --limit")
  error("The job requires a list of hosts to limit the run.")
else:
  job_data['limit'] = args.limit

try:
  job_started = awxpost('/job_templates/%s/launch/' % template_number, data=job_data)
  #print json.dumps(job_started.json(), indent=2)
  if(job_started.json()['id'] and job_started.json()['job']):
    job_number = job_started.json()['id']
    job_status = "STARTED"
    log_run("OK: job started")
    info("Tower job %s started." % job_number)
  else:
    job_status = "FAILED"
    log_run("ERROR: API call to start job failed")
    error("Could not start tower job: %s" % job_started['result_stdout'])
except:
  log_run("ERROR: bad request on API call -- URI[/job_templates/%s/launch/] DATA[%s] RESPONSE[%s]" % (template_number, job_data, job_started.text))
  error("There was a bad request on the API call -- URI[/job_templates/%s/launch/] DATA[%s] RESPONSE[%s]" % (template_number, job_data, job_started.text))
