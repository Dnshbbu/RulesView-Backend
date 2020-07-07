# RulesView-Backend
This repository is to store the backend code for RulesView Application

## Dependencies
1. Neo4j database
      - **JAVA** dependency

## Steps to reproduce the Frontend of RulesView

### Setup Neo4j
1. Download Neo4j community edition from [Neo4j Downloads](https://neo4j.com/download-center/#community)
2. Check the apoc [Version compatibility matrix](https://github.com/neo4j-contrib/neo4j-apoc-procedures#:~:text=APOC%20is%20easily%20installed%20with,box%20and%20you're%20done.) and download the JAR file matching with the version of neo4j. Place the jar file in the **plugins** directory of neo4j
3. Add the following lines to the bottom of **neo4j.conf** file in **conf** directory 
```
      dbms.security.procedures.unrestricted=apoc.*
      dbms.security.procedures.whitelist=apoc.*
      apoc.export.file.enabled=true
      apoc.import.file.enabled=true
```
4. Start the neo4j service by browsing to the bin directory in terminal and type ``neo4j.bat console``
5. If you get a non compatible JAVA version error. Download and install the required JDK.
6. Set the **JAVA_HOME** path variable (Windows: [PATH](https://stackoverflow.com/questions/1618280/where-can-i-set-path-to-make-exe-on-windows)) to the installed JDK (Example: ``C:\Program Files\Java\jdk-11.0.7``)
7. Now, Start the neo4j service by browsing to the bin directory in terminal and type ``neo4j.bat console``
8. Check whether Neo4j is setup correctly by browsing to ``http://localhost:7474/``. The default username and password is neo4j/neo4j. You have to change the password after first login.
9. If everything configured correctly, your neo4j service is now running.

### Setup python
1. Create a virtual environment ``python -m venv env``
2. In windows, Activate the virtual environment ``.\env\Scripts\activate``
3. Install all the pip requirements in the virtual environment  ``pip install -r requirements.txt``
4. Update the ``conf\creds.ini`` file within the neo4j import directory path(absolute path Ex: ``C:\users\desktopuser\Downloads\neo4j-community-4.0.6-windows\neo4j-community-4.0.6\import``)
5. Run ``python RunBackend.py`` to start the Flask server
6. If everything configured correctly, your python backend flask server is now running.

### Technology stack
1. [Python3](https://www.python.org/downloads/)
2. [Flask framework](https://flask.palletsprojects.com/en/1.1.x/)
3. [Neo4j](https://neo4j.com/)



######


