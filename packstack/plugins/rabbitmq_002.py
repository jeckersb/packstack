"""
Installs and configures rabbitmq
"""

import logging
import uuid
import os

from packstack.installer import validators
from packstack.installer import basedefs
from packstack.installer import utils

from packstack.modules.common import filtered_hosts
from packstack.modules.ospluginutils import gethostlist,\
                                            getManifestTemplate,\
                                            appendManifestFile

# Controller object will be initialized from main flow
controller = None

# Plugin name
PLUGIN_NAME = "OS-RABBITMQ"
PLUGIN_NAME_COLORED = utils.color_text(PLUGIN_NAME, 'blue')

logging.debug("plugin %s loaded", __name__)

def initConfig(controllerObject):
    global controller
    controller = controllerObject
    logging.debug("Adding OpenStack RabbitMQ configuration")
    paramsList = [
                  {"CMD_OPTION"      : "rabbitmq-host",
                   "USAGE"           : "The IP address of the server on which to install the RabbitMQ service",
                   "PROMPT"          : "Enter the IP address of the RabbitMQ service",
                   "OPTION_LIST"     : [],
                   "VALIDATORS"      : [validators.validate_ssh],
                   "DEFAULT_VALUE"   : utils.get_localhost_ip(),
                   "MASK_INPUT"      : False,
                   "LOOSE_VALIDATION": True,
                   "CONF_NAME"       : "CONFIG_RABBITMQ_HOST",
                   "USE_DEFAULT"     : False,
                   "NEED_CONFIRM"    : False,
                   "CONDITION"       : False },
                  {"CMD_OPTION"      : "rabbitmq-enable-ssl",
                   "USAGE"           : "Enable SSL for the RabbitMQ service",
                   "PROMPT"          : "Enable SSL for the RabbitMQ service?",
                   "OPTION_LIST"     : ["y", "n"],
                   "VALIDATORS"      : [validators.validate_options],
                   "DEFAULT_VALUE"   : "n",
                   "MASK_INPUT"      : False,
                   "LOOSE_VALIDATION": False,
                   "CONF_NAME"       : "CONFIG_RABBITMQ_ENABLE_SSL",
                   "USE_DEFAULT"     : False,
                   "NEED_CONFIRM"    : False,
                   "CONDITION"       : False },
                  {"CMD_OPTION"      : "rabbitmq-enable-auth",
                   "USAGE"           : "Enable Authentication for the RabbitMQ service",
                   "PROMPT"          : "Enable Authentication for the RabbitMQ service?",
                   "OPTION_LIST"     : ["y", "n"],
                   "VALIDATORS"      : [validators.validate_options],
                   "DEFAULT_VALUE"   : "n",
                   "MASK_INPUT"      : False,
                   "LOOSE_VALIDATION": False,
                   "CONF_NAME"       : "CONFIG_RABBITMQ_ENABLE_AUTH",
                   "USE_DEFAULT"     : False,
                   "NEED_CONFIRM"    : False,
                   "CONDITION"       : False },


                  ]


    groupDict = { "GROUP_NAME"            : "RABBITMQLANCE",
                  "DESCRIPTION"           : "RabbitMQ Config parameters",
                  "PRE_CONDITION"         : check_enabled,
                  "PRE_CONDITION_MATCH"   : True,
                  "POST_CONDITION"        : False,
                  "POST_CONDITION_MATCH"  : True}

    controller.addGroup(groupDict, paramsList)

    paramsList = [
                  {"CMD_OPTION"      : "rabbitmq-nss-certdb-pw",
                   "USAGE"           : "The password for the NSS certificate database of the RabbitMQ service",
                   "PROMPT"          : "Enter the password for NSS certificate database",
                   "OPTION_LIST"     : [],
                   "VALIDATORS"      : [validators.validate_not_empty],
                   "DEFAULT_VALUE"   : uuid.uuid4().hex[:32],
                   "MASK_INPUT"      : False,
                   "LOOSE_VALIDATION": True,
                   "CONF_NAME"       : "CONFIG_RABBITMQ_NSS_CERTDB_PW",
                   "USE_DEFAULT"     : False,
                   "NEED_CONFIRM"    : False,
                   "CONDITION"       : False },
                  {"CMD_OPTION"      : "rabbitmq-ssl-port",
                   "USAGE"           : "The port in which the RabbitMQ service listens to SSL connections",
                   "PROMPT"          : "Enter the SSL port for the RabbitMQ service",
                   "OPTION_LIST"     : [],
                   "VALIDATORS"      : [validators.validate_not_empty],
                   "DEFAULT_VALUE"   : "5671",
                   "MASK_INPUT"      : False,
                   "LOOSE_VALIDATION": True,
                   "CONF_NAME"       : "CONFIG_RABBITMQ_SSL_PORT",
                   "USE_DEFAULT"     : False,
                   "NEED_CONFIRM"    : False,
                   "CONDITION"       : False },
                  {"CMD_OPTION"      : "rabbitmq-ssl-cert-file",
                   "USAGE"           : "The filename of the certificate that the RabbitMQ service is going to use",
                   "PROMPT"          : "Enter the filename of the SSL certificate for the RabbitMQ service",
                   "OPTION_LIST"     : [],
                   "VALIDATORS"      : [validators.validate_not_empty],
                   "DEFAULT_VALUE"   : "/etc/pki/tls/certs/rabbitmq_selfcert.pem",
                   "MASK_INPUT"      : False,
                   "LOOSE_VALIDATION": True,
                   "CONF_NAME"       : "CONFIG_RABBITMQ_SSL_CERT_FILE",
                   "USE_DEFAULT"     : False,
                   "NEED_CONFIRM"    : False,
                   "CONDITION"       : False },
                  {"CMD_OPTION"      : "rabbitmq-ssl-key-file",
                   "USAGE"           : "The filename of the private key that the RabbitMQ service is going to use",
                   "PROMPT"          : "Enter the private key filename",
                   "OPTION_LIST"     : [],
                   "VALIDATORS"      : [validators.validate_not_empty],
                   "DEFAULT_VALUE"   : "/etc/pki/tls/private/rabbitmq_selfkey.pem",
                   "MASK_INPUT"      : False,
                   "LOOSE_VALIDATION": True,
                   "CONF_NAME"       : "CONFIG_RABBITMQ_SSL_KEY_FILE",
                   "USE_DEFAULT"     : False,
                   "NEED_CONFIRM"    : False,
                   "CONDITION"       : False },
                  {"CMD_OPTION"      : "rabbitmq-ssl-self-signed",
                   "USAGE"           : "Auto Generates self signed SSL certificate and key",
                   "PROMPT"          : "Generate Self Signed SSL Certificate",
                   "OPTION_LIST"     : ["y","n"],
                   "VALIDATORS"      : [validators.validate_not_empty],
                   "DEFAULT_VALUE"   : "y",
                   "MASK_INPUT"      : False,
                   "LOOSE_VALIDATION": True,
                   "CONF_NAME"       : "CONFIG_RABBITMQ_SSL_SELF_SIGNED",
                   "USE_DEFAULT"     : False,
                   "NEED_CONFIRM"    : False,
                   "CONDITION"       : False },
                 ]

    groupDict = { "GROUP_NAME"            : "RABBITMQSSL",
                  "DESCRIPTION"           : "RabbitMQ Config SSL parameters",
                  "PRE_CONDITION"         : check_ssl_enabled,
                  "PRE_CONDITION_MATCH"   : True,
                  "POST_CONDITION"        : False,
                  "POST_CONDITION_MATCH"  : True}

    controller.addGroup(groupDict, paramsList)

    paramsList = [
                  {"CMD_OPTION"      : "rabbitmq-auth-user",
                   "USAGE"           : "User for rabbitmq authentication",
                   "PROMPT"          : "Enter the user for rabbitmq authentication",
                   "OPTION_LIST"     : [],
                   "VALIDATORS"      : [validators.validate_not_empty],
                   "DEFAULT_VALUE"   : "rabbitmq_user",
                   "MASK_INPUT"      : False,
                   "LOOSE_VALIDATION": True,
                   "CONF_NAME"       : "CONFIG_RABBITMQ_AUTH_USER",
                   "USE_DEFAULT"     : False,
                   "NEED_CONFIRM"    : False,
                   "CONDITION"       : False },
                  {"CMD_OPTION"      : "rabbitmq-auth-password",
                   "USAGE"           : "Password for user authentication",
                   "PROMPT"          : "Enter the password for user authentication",
                   "OPTION_LIST"     : ["y", "n"],
                   "VALIDATORS"      : [validators.validate_not_empty],
                   "DEFAULT_VALUE"   : uuid.uuid4().hex[:16],
                   "MASK_INPUT"      : False,
                   "LOOSE_VALIDATION": True,
                   "CONF_NAME"       : "CONFIG_RABBITMQ_AUTH_PASSWORD",
                   "USE_DEFAULT"     : False,
                   "NEED_CONFIRM"    : False,
                   "CONDITION"       : False },

                  ]

    groupDict = { "GROUP_NAME"            : "RABBITMQAUTH",
                  "DESCRIPTION"           : "RabbitMQ Config Athentication parameters",
                  "PRE_CONDITION"         : "CONFIG_RABBITMQ_ENABLE_AUTH",
                  "PRE_CONDITION_MATCH"   : "y",
                  "POST_CONDITION"        : False,
                  "POST_CONDITION_MATCH"  : True}


    controller.addGroup(groupDict, paramsList)
def check_ssl_enabled(config):
    return check_enabled(config) and config.get('CONFIG_RABBITMQ_ENABLE_SSL') == 'y'


def check_enabled(config):
    return (config.get('CONFIG_NOVA_INSTALL') == 'y' or
        config.get('CONFIG_RABBITMQ_HOST') != '')

def initSequences(controller):
    rabbitmqsteps = [
             {'title': 'Adding RabbitMQ manifest entries', 'functions':[createmanifest]}
    ]
    controller.addSequence("Installing RabbitMQ", [], [], rabbitmqsteps)

def createmanifest(config):
    manifestfile = "%s_rabbitmq.pp"%config['CONFIG_RABBITMQ_HOST']
    manifestdata = ""
    ssl_manifestdata = ""
    server = utils.ScriptRunner(config['CONFIG_RABBITMQ_HOST'])
    if config['CONFIG_RABBITMQ_ENABLE_SSL'] == 'y':
        config['CONFIG_RABBITMQ_ENABLE_SSL'] = 'true'
        config['CONFIG_RABBITMQ_PROTOCOL'] = 'ssl'
        config['CONFIG_RABBITMQ_CLIENTS_PORT'] = "5671"
        if config['CONFIG_RABBITMQ_SSL_SELF_SIGNED'] == 'y':
            server.append( "openssl req -batch -new -x509 -nodes -keyout %s -out %s -days 1095"
                % (config['CONFIG_RABBITMQ_SSL_KEY_FILE'], config['CONFIG_RABBITMQ_SSL_CERT_FILE']) )
            server.execute()
        ssl_manifestdata = getManifestTemplate('rabbitmq_ssl.pp')
    else:
        #Set default values
        config['CONFIG_RABBITMQ_CLIENTS_PORT'] = "5672"
        config['CONFIG_RABBITMQ_SSL_PORT'] = "5671"
        config['CONFIG_RABBITMQ_SSL_CERT_FILE'] = ""
        config['CONFIG_RABBITMQ_SSL_KEY_FILE'] = ""
        config['CONFIG_RABBITMQ_NSS_CERTDB_PW'] = ""
        config['CONFIG_RABBITMQ_ENABLE_SSL'] = 'false'
        config['CONFIG_RABBITMQ_PROTOCOL'] = 'tcp'

    manifestdata = getManifestTemplate('rabbitmq.pp')
    manifestdata += ssl_manifestdata

    if config['CONFIG_RABBITMQ_ENABLE_AUTH'] == 'y':
        manifestdata += getManifestTemplate('rabbitmq_auth.pp')
    else:
        config['CONFIG_RABBITMQ_AUTH_PASSWORD'] = 'guest'
        config['CONFIG_RABBITMQ_AUTH_USER'] = 'guest'

    #All hosts should be able to talk to rabbitmq
    hosts = ["'%s'" % i for i in filtered_hosts(config, exclude=False)]
    # if the rule already exists for one port puppet will fail
    # so i had to add always both rabbitmq ports (plain and SSL) in order
    # to avoid rule changes, this is due some problematic behaviour of
    # the puppet firewall module
    # this is a temporary solution, as soon as the firewall module is
    # updated we'll go back to previous state in which we open just
    # the needed ports
    config['FIREWALL_ALLOWED'] = ','.join(hosts)
    config['FIREWALL_SERVICE_NAME'] = "rabbitmq"
    config['FIREWALL_PORTS'] =  "'5671', '5672'"
    manifestdata += getManifestTemplate("firewall.pp")

    appendManifestFile(manifestfile, manifestdata, 'pre')
