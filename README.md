# IBM ASoC to Code Dx Converter

This converter uses data from the IBM Application Security on Cloud to create findings
inside of Code Dx.  Both systems are accessed using their respective APIs and authorization
systems.

A file is used to obtain various operating parameters.
We will examine each section (there are two; one for Code Dx, and another for ASoC).

```
[CodeDx]
transport = https
addr   = demo.codedx.tech
port   = 80
apikey = f3453a48-ff13-4c53-a1ad-47302066cf5c
project = asoc
```
Code Dx uses an API key that will be used for authorization of the operations the script
wishes to perform.  It is obtained by logging into your Code Dx server as anyone with
administration rights, and moving to the `Admin` page on the black navigation bar.

Generation of the API Key is done on this page.  See the buttons on the middle right to
create a key for your use.  Be sure that the key is **_not_** given administrative rights
to preserve your server security.  However, ensure the API key is given permissions to the
project that is specified above in your Code Dx project.

Most of the information presented in the `Code Dx` section is pretty evident.
`transport` may be HTTP or HTTPS, `port` defines the Code Dx server port and should be set
to 80 (standard HTTP), or 443 (standard HTTPS).  If no port is given, then the default
is used.

``addr`` may be a DNS name (e.g. `demo.codedx.tech`) or a standard dot-notation address.  

``project`` should point to the project that will be the Code Dx recipient of the incoming
findings.  Note that the spelling for it should match the Code Dx server.

``Note that the current implementation of this script does NOT push the findings from
IBM ASoC into Code Dx.  It generates an XML file that is formatted in the Code Dx schema.
That file may be used in an analysis by Code Dx.``

```
[ASOC]
transport = https
addr = appscan.ibmcloud.com
application = demo Android
keyId = 826c37f2-5386-9594-ec05-3534e5ccd5ba
keySecret = fD42fTmf1nq3HMtsNdi/kTsuQyJh1YknCGNZkwo/fjY=
#user = vincent.hopson@codedx.com
#password = myASOCpassword
accessTokenFile = access_token.json
```

In this case, `transport`, `addr`, and `application` mean the same thing as they do in
Code Dx, but refer to the IBM ASoC server.  There are two methods of accessing information.
In one, a `keyId` is generated, and used with the `keySecret`.  In the other method,
a standard `user`, and `password` are used.  One of these methods **must** be used or
the script will fail.  It should be evident in the failure what went wrong.

Finally, the `accessTokenFile` is used to keep the authorization token for the period of
time the token is good for.  This minimizes accesses to the ASoC server to acquire a token
as each token is good for a couple of hours.  All accesses to the ASoC server require this
to be used.  The token file is simply generated, and left.  A policy to destroy the file
may be created, but this script does not enforce removal.

Both of the previous sections should be in the same configuration file.  You point your
operation at that configuration file when creating the `codedx.xml` output file.

## Using the Script

Use of the script is pretty easy once the configuration file is created.  Note that **only** 
files that will be in the current directory before running the script are:

* The configuration file with the above specified contents
* asoc2codedx.py - the script that is executed to perform the data acquisition
* asoc.py - a support file that contains access code for the IBM ASoC

After successful execution of the script, three additional files will be generated in the
current working directory.  These are:

* codedx.xml - the output from IBM ASoC for Code Dx ingestion
* access_token.json - or the name definedby this element of the configuration file

A sample command using the script is below:

```bash
python asoc2codedx.py -c asoc.ini
```

## Important Notes

Note that submission to the Code Dx server is not done automatically.  The generation of
the XML information from the IBM ASoC project is placed into ``codedx.xml``.  Currently,
there are no planned changes to:

* Push the Code Dx data into the Code Dx server.  The information in the `CodeDx` section
is for future enhancement
* Remove the `access_token.json` file for security, or modify the permissions to limit
access by unauthorized personnel.