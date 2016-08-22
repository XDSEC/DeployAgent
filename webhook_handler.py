from flask import Flask
from flask import request
import pyotp
import os
import json
import logging
from logging.handlers import RotatingFileHandler
import hashlib
import hmac
import sys


CONFIG_PATH=sys.argv[3]

app=Flask(__name__)

def log(payload):
	commits=payload['commits']
	added_files=[]
	removed_files=[]
	modified_files=[]
	for index in range(len(commits)):
		added_files+=commits[index]['added']
		removed_files+=commits[index]['removed']
		modified_files+=commits[index]['modified']

	sender=payload['sender']['login']
	branch=payload['ref'].split('/')[-1]
	sender_is_site_admin=payload['sender']['site_admin']

	logging.info('Branch:{}  Added files:{}  Modified files:{}  Removed files:{}\
              Sender:{} isSiteAdmin:{}'
                .format(str(branch),
						str(added_files),
                        str(modified_files),
                        str(removed_files),
                        str(sender),
                        str(sender_is_site_admin),
                        ))

def load_config(path=CONFIG_PATH):
	try:
		with open(path) as f:
			config=json.load(f)
	except Exception as e:
		print (e)
		logging.critical("Failed to open config file '{}'.".format(path))
		return False
	try:
		global DEPLOY_PATHS
		global CHECK_FILES
		global GIT_ADDRESS
		global TOTP_SEED
		global GITHUB_SECRET
		global ALLOW_BRANCHES

		ALLOW_BRANCHES=config['allow_branches']
		DEPLOY_PATHS=config['deploy_paths']
		CHECK_FILES=config['check_files']
		GIT_ADDRESS=config['git_address']
		TOTP_SEED=config['totp_seed']
		GITHUB_SECRET=config['github_secret']

		return True
	except:
		logging.critical("Failed to load config.")
		return False

def deploy(deploy_path,branch):
	try:
		cmd="cd {};git checkout {};git pull".format(deploy_path,branch)
		result=os.popen(cmd).read()
		print (result)
		logging.info('Deployed succeed.')
	except:
		logging.critical('Deployed failed.')

def check_signature(signature,data):
	try:
		signature=signature.split('=')[-1]
		load_config()
		mac = hmac.new(GITHUB_SECRET.encode(), msg=data,\
                 digestmod=hashlib.sha1).hexdigest()
		result=hmac.compare_digest(mac, str(signature))
	except:
		logging.warning("Some thing wrong while checking signature.")
		return False

	if result:
		return True
	else:
		logging.warning('Signatures didn\'t match! {} && {}(local)'.\
                  format(signature,mac))
		return False

def check_permission(payload):
	with open('check_totp_flag','r') as f:
		if f.read():
			logging.warning('Refuse deploy.\
                   Because the check_totp_flag is True.')
			return 1

	if not load_config():
		return 0

	branch=payload['ref'].split('/')[-1]
	if branch not in ALLOW_BRANCHES:
		logging.info('Refuse deploy. Because the branch doesn\'t in the allow branches.')
		return 3

	commits=payload['commits']
	added_files=[]
	removed_files=[]
	modified_files=[]
	for index in range(len(commits)):
		added_files+=commits[index]['added']
		removed_files+=commits[index]['removed']
		modified_files+=commits[index]['modified']

	for item in CHECK_FILES:
		if item in added_files+removed_files+modified_files:
			with open('check_totp_flag','w') as f:
				f.write('1')
			logging.warning('Refuse deploy.\
                   Because there are some files needed to be checked by TOTP.')
			return 1
	return 2

@app.route('/deploy',methods=['POST'])
def webhook_handle():
	data=request.data
	payload=request.json
	signature=request.headers.get('X-Hub-Signature')

	if not check_signature(signature,data=data):
		return 'Are you crazzzzzzzzzy!'

	if not load_config():
		return '500'

	log(payload)

	result=check_permission(payload)
	if result == 0:
		return '500'
	elif result == 1:
		return 'Sorry. Can\'t deploy right now.\
            Because there are some files needed to be checked by admin.'
	elif result == 2:
		branch=payload['ref'].split('/')[-1]
		deploy_path=DEPLOY_PATHS[branch]
		deploy(deploy_path,branch)
		return 'Deployed'
	elif result == 3:
		return 'Sorry. Can\'t deploy. Because the branch doesn\'t in the allow branches.'

@app.route('/auth/<totp>',methods=['GET'])
def check_totp_handle(totp):
	if not load_config():
		return "Are you crazzzzzzzy!"
	result=pyotp.TOTP(TOTP_SEED).verify(totp)
	if not result:
		logging.warning('TOTP Authentication failed: {}'.format(totp))
		return "Are you crazzzzzzzy!"
	logging.info('TOTP Authentication succeed: {}'.format(totp))
	deploy()
	with open('check_totp_flag','w') as f:
		f.write('')
	return "Deployed"

def init_logging():
	logging.basicConfig(
		level=logging.INFO,
		format='%(asctime)s  %(levelname)-8s [+]%(message)s',
		datefmt='%d %b %Y %H:%M:%S',
	)

	Rthandler = RotatingFileHandler('webhook_handler_log',\
                                 maxBytes=1024*1024,backupCount=2)
	Rthandler.setLevel(logging.INFO)
	formatter=logging.Formatter('%(asctime)s  %(levelname)-8s %(message)s')
	Rthandler.setFormatter(formatter)
	logging.getLogger('').addHandler(Rthandler)

def check_deploy_dir(deploy_path):
	if not load_config():
		return False
	if os.path.isdir(deploy_path):
		if os.listdir(deploy_path):
			if os.path.exists(deploy_path+"/.git/"):
				return True
			else:
				logging.critical("{} is not a Git directory.".format(deploy_path))
		else:
			result=os.system("git clone {} {}".format(GIT_ADDRESS,deploy_path))
			if result != 0:
				logging.critical('Failed to clone from {}'.format(GIT_ADDRESS))
				return False
			logging.info("Cloned from {}".format(GIT_ADDRESS))
			return True
	else:
		logging.critical('Directory {} doesn\'t exist.'.format(deploy_path))
		return False

def init():
	if not os.path.exists('check_totp_flag'):
		with open('check_totp_flag','w') as f:
			f.write('')
	init_logging()
	load_config()
	print (DEPLOY_PATHS)
	for branch in DEPLOY_PATHS:
		if not check_deploy_dir(DEPLOY_PATHS[branch]):
			os._exit(0)


if __name__ == '__main__':
	init()
	app.run(host=sys.argv[1],port=sys.argv[2])
