# UAA Invites

This application recreates the invite functionality that previously existed in UAA by using the /invite_users API endpoint.

### Installing the App

#### Step One: Determine the URL for your instance of UAA Invites

You'll need to know where the app is going to be hosted, so you can tell UAA about it in the next step.

For example, if you'll be deploying into Cloudfoundry on BOSH-lite your url would probably be http://invite.bosh-lite.com/

#### Step Two: Create a client in UAA for this app

This application uses oauth to perform actions on your behalf in UAA.  To add a new oauth client in UAA, run the following command:

	uaac client add [your-client-id] --name "UAA Invites" --scope "scim.invite" --authorized_grant_types "authorization_code" --redirect_uri [url-from-step-one]/oauth/login -s [your-client-secret]

Remember the client-id and client-secret, you'll need them in the next step

#### Step Three: Configure the app

The configuration is entirely read from environment variables. Edit the manifest.yml files and update your settings as neccessary

#### Step Four: Ensure your UAA user has the proper scopes/groups

Your UAA user must have the scim.invite scopes/group membership

	uaac member add scim.invite [your-uaa-login]

#### Step Five: Launch the app

This app was designed to run in Cloud Foundry:

	cf push

You can also run it locally in debug mode:

	# set configuration env vars as needed
	./debug.py
