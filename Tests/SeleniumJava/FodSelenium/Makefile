
# wrapper for maven and running of compiled Tests assuming debian buster 
#

help:
	@grep -E "^[a-zA_Z_][^ :]+:" Makefile

all:
	-#echo "vncviewer -via test-fodd-lab-1.geant.net 172.18.0.3:0"
	echo "vncviewer -via $(FOD_UI_GW:-$(hostname -i)) $(hostname -i):0"
	echo make FOD_USER="$(FOD_USER)" FOD_PWD="$(FOD_PWD)" runtest1

##

ensuremaven:
	which mvn | grep -q . || apt-get install -qyy maven

##

ensurevnc0running00:
	which Xvnc | grep -q . || apt-get install -qyy tightvncserver 
	which xterm | grep -q . || apt-get install -qyy xterm
	which xdpyinfo | grep -q . || apt-get install -qyy x11-utils

ensurevnc0running01:
	DISPLAY=:0 xdpyinfo >/dev/null && echo "xserver already ok" || make startvnc0

ensurevnc0running0: ensurevnc0running00 ensurevnc0running01

ensurevnc0running: ensuretestuser1
	make ensurevnc0running00
	which sudo | grep -q . || apt-get install -qyy sudo
	sudo -u test1 make ensurevnc0running01

##

ensuretestuser1:
	id test1 || useradd -m -s /bin/bash test1

startvnc0:
	Xvnc -geometry 1900x1024 -depth 24 :0 & 
	sleep 1
	DISPLAY=:0 xdpyinfo >/dev/null && echo "xserver/vnc ok"
	DISPLAY=:0 xterm &

##

ensurechromedriver:
	test -x /usr/local/bin/chromedriver || make installchromedriver

installchromedriver:
	which chromium-browser &>/dev/null || apt-get install -qqy chromium || apt-get install chromium-browser  #firefox-esr 
	apt-get install -qyy curl unzip openjdk-11-jre-headless xvfb libxi6 libgconf-2-4 gnupg2
	curl -sS -o - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add
	echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list
	apt-get -y update
	apt-get -y install google-chrome-stable
	apt-get -y install tidy

	# TODO: find an suitable version:
	#RUN wget -N https://chromedriver.storage.googleapis.com/$(google-chrome --version | grep -Eo "[0-9\.]+")/chromedriver_linux64.zip -P /root/
	#wget -N https://chromedriver.storage.googleapis.com/89.0.4389.23/chromedriver_linux64.zip -P /root
	#wget -N https://chromedriver.storage.googleapis.com/90.0.4430.24/chromedriver_linux64.zip -P /root
	chromium_version="$$(google-chrome --version | grep -Eo "[0-9\.]+" | grep -Eo "^[0-9]+")"; \
	echo "chromium_version=$$chromium_version" 1>&2 ; \
	driver_version="$$(curl https://chromedriver.storage.googleapis.com | tidy -xml | grep -Eo "$$chromium_version"'\.0\.[0-9]+\.[0-9]+' | sort -s -u | head -1)"; \
	echo "driver_version=$$driver_version" 1>&2 ; \
	wget -N "https://chromedriver.storage.googleapis.com/$$driver_version/chromedriver_linux64.zip" -P /root
	#wget -N https://chromedriver.storage.googleapis.com/91.0.4472.19/chromedriver_linux64.zip -P /root
	unzip /root/chromedriver_linux64.zip -d /root
	mv -f /root/chromedriver /usr/local/bin/chromedriver
	chown root:root /usr/local/bin/chromedriver
	#chmod 0755 /usr/local/bin/chromedriver

##

clean: ensuremaven
	if [ "$$(id -u)" = 0 ]; then \
	  echo using sudo user; \
	  chown -R test1 ../../..; \
	  sudo -u test1 env DISPLAY=:0 mvn clean; \
	else \
	  echo user; \
	  mvn clean; \
	fi

# -Dmaven.test.skip=true -D
#mvn clean compile package assembly:single
package1: ensuremaven
	if [ "$$(id -u)" = 0 ]; then \
	  echo using sudo user; \
	  chown -R test1 ../../..; \
	  sudo -u test1 env DISPLAY=:0 mvn -Dmaven.test.skip=true compile package assembly:single; \
	else \
	  echo "user $$(id -un)"; \
	  mvn -Dmaven.test.skip=true compile package assembly:single; \
	fi

mvntest1: ensuremaven
	if [ "$$(id -u)" = 0 ]; then \
	  echo using sudo user; \
	  chown -R test1 ../../..; \
	  sudo -u test1 env DISPLAY=:0 mvn test; \
	else \
	  echo "user $$(id -un)"; \
	  mvn test; \
	fi

###

#CLASS1:=Login
CLASS1:=LoginTest

#TEST_DIR:=src/Tests
TEST_DIR:=src/test/java/Tests

chg_src_login_url0:
	echo "$(LOGIN_URL1)" > "$(TEST_DIR)/.$(CLASS1).url.$$"
	if [ "$(TEST_DIR)/$(CLASS1).java" -nt "$(TEST_DIR)/.$(CLASS1).url" ] || ! diff "$(TEST_DIR)/.$(CLASS1).url.$$" "$(TEST_DIR)/.$(CLASS1).url"; then \
	  mv -f "$(TEST_DIR)/.$(CLASS1).url.$$" "$(TEST_DIR)/.$(CLASS1).url"; \
	  sed -i  -r 's/url *=.*/url = "$(LOGIN_URL1)\/altlogin";/' $(TEST_DIR)/$(CLASS1).java; \
	fi
	echo "$(LOGIN_USER1)" > "$(TEST_DIR)/.$(CLASS1).user.$$"
	if [ "$(TEST_DIR)/$(CLASS1).java" -nt "$(TEST_DIR)/.$(CLASS1).user" ] || ! diff "$(TEST_DIR)/.$(CLASS1).user.$$" "$(TEST_DIR)/.$(CLASS1).user"; then \
	  mv -f "$(TEST_DIR)/.$(CLASS1).user.$$" "$(TEST_DIR)/.$(CLASS1).user"; \
	  sed -i  -r 's/"id_username".*sendKeys.*$$/"id_username"\)\).sendKeys\("'"$(LOGIN_USER1)"'"\)\;/' $(TEST_DIR)/$(CLASS1).java; \
	fi
	echo "$(LOGIN_PWD1)" > "$(TEST_DIR)/.$(CLASS1).pwd.$$"
	if [ "$(TEST_DIR)/$(CLASS1).java" -nt "$(TEST_DIR)/.$(CLASS1).pwd" ] || ! diff "$(TEST_DIR)/.$(CLASS1).pwd.$$" "$(TEST_DIR)/.$(CLASS1).pwd"; then \
	  mv -f "$(TEST_DIR)/.$(CLASS1).pwd.$$" "$(TEST_DIR)/.$(CLASS1).pwd"; \
	  sed -i  -r 's/"id_password".*sendKeys.*$$/"id_password"\)\).sendKeys\("'"$(LOGIN_PWD1)"'"\)\;/' $(TEST_DIR)/$(CLASS1).java; \
	fi

chg_src_login_url1: chg_src_login_url0
	make ./target/fodselenium-0.0.1-SNAPSHOT-jar-with-dependencies.jar

java_file_list=$(wildcard $(TEST_DIR)/*.java)
url_file_list=$(wildcard $(TEST_DIR)/*.url)

#./target/fodselenium-0.0.1-SNAPSHOT-jar-with-dependencies.jar: src/Tests/Login.url $(url_file_list) $(java_file_list)
./target/fodselenium-0.0.1-SNAPSHOT-jar-with-dependencies.jar: $(java_file_list)
	make package1

FOD_IP = $(shell echo "$${FOD_IP:-172.17.0.2}")
FOD_PORT = $(shell echo "$${FOD_PORT:-8000}")
FOD_USER = $(shell echo "$${FOD_USER:-admin}")
FOD_PWD = $(shell echo "$${FOD_PWD:-adminpwd1}")

run1: ensurechromedriver ensuretestuser1
	#sed -i  -r 's/^(\s*String url =).*/\1 "http:\/\/172.17.0.2:8000\/altlogin";/' src/Tests/Login.java
	#make package1
	echo "FOD_IP=$(FOD_IP)" 1>&2
	make chg_src_login_url1 LOGIN_URL1='http:\/\/$(FOD_IP):$(FOD_PORT)' LOGIN_USER1='$(FOD_USER)' LOGIN_PWD1='$(FOD_PWD)' CLASS1="$(CLASS1)"
	chown -R test1 ../../..
	make ./target/fodselenium-0.0.1-SNAPSHOT-jar-with-dependencies.jar
	ln -sf /usr/local/bin/chromedriver .\\driver\\chromedriver.exe
	echo "X server (e.g. vnc) should be running on :0 and be accessible for test 1 user" 1>&2
	#xdpyinfo
	make ensurevnc0running
	#DISPLAY=:0 java -cp ./target/fodselenium-0.0.1-SNAPSHOT-jar-with-dependencies.jar Tests.Login
	#sudo -u test1 env DISPLAY=:0 java -cp ./target/fodselenium-0.0.1-SNAPSHOT-jar-with-dependencies.jar Tests.Login
	sudo -u test1 env DISPLAY=:0 java -cp ./target/fodselenium-0.0.1-SNAPSHOT-jar-with-dependencies.jar "Tests.$(CLASS1)"


updateclasssrc-%:
	echo "FOD_IP=$(FOD_IP) FOD_PORT=$(FOD_PORT) FOD_USER=$(FOD_USER) FOD_PWD=$(FOD_PWD)" 1>&2
	make chg_src_login_url0 LOGIN_URL1='http:\/\/$(FOD_IP):$(FOD_PORT)' LOGIN_USER1='$(FOD_USER)' LOGIN_PWD1='$(FOD_PWD)' CLASS1="$*"

updateclass-%:
	echo "FOD_IP=$(FOD_IP) FOD_PORT=$(FOD_PORT) FOD_USER=$(FOD_USER) FOD_PWD=$(FOD_PWD)" 1>&2
	make chg_src_login_url0 LOGIN_URL1='http:\/\/$(FOD_IP):$(FOD_PORT)' LOGIN_USER1='$(FOD_USER)' LOGIN_PWD1='$(FOD_PWD)' CLASS1="$*"

CLASSES0:=$(wildcard $(TEST_DIR)/*.java)
CLASSES_update_src_list:=$(patsubst $(TEST_DIR)/%.java,updateclasssrc-%,$(CLASSES0))
CLASSES_update_list:=$(patsubst $(TEST_DIR)/%.java,updateclass-%,$(CLASSES0))

updateclasssrces: $(CLASSES_update_src_list)
	echo CLASSES0=$(CLASSES0) 1>&2
	echo CLASSES_update_src_list=$(CLASSES_update_src_list) 1>&2
	#make $(CLASSES_update_src_list)
	#make ./target/fodselenium-0.0.1-SNAPSHOT-jar-with-dependencies.jar

updateclasses: $(CLASSES_update_list)
	echo CLASSES0=$(CLASSES0) 1>&2
	echo CLASSES_update_list=$(CLASSES_update_list) 1>&2
	make $(CLASSES_update_list)
	make ./target/fodselenium-0.0.1-SNAPSHOT-jar-with-dependencies.jar

updateconf:
	sed -i  -r 's/^url=.*/url=http:\/\/$(FOD_IP):$(FOD_PORT)/' configs/Configuration.properties
	sed -i  -r 's/^login=.*/login=$(FOD_USER)/' configs/Configuration.properties
	sed -i  -r 's/^password=.*/password=$(FOD_PWD)/' configs/Configuration.properties

updateclasses2: updateconf

echoinfo:
	@echo "settings used: FOD_IP=$(FOD_IP) FOD_PORT=$(FOD_PORT) FOD_USER=$(FOD_USER) FOD_PWD=$(FOD_PWD), waiting 10 seconds" 1>&2
	sleep 10

runtest1: echoinfo runtest0
	@true

# use mvn for running all tests
runtest0: echoinfo ensurechromedriver ensuretestuser1 updateclasses2
	#make chg_src_login_url1 LOGIN_URL1='http:\/\/172.17.0.2:8000' LOGIN_USER1='XXXX' LOGIN_PWD1='YYYYYY' CLASS1="$(CLASS1)"
	#make updateclass-LoginTest
	echo "FOD_IP=$(FOD_IP)" 1>&2
	chown -R test1 ../../..
	make ./target/fodselenium-0.0.1-SNAPSHOT-jar-with-dependencies.jar
	ln -sf /usr/local/bin/chromedriver .\\driver\\chromedriver.exe
	echo "X server (e.g. vnc) should be running on :0 and be accessible for test 1 user" 1>&2
	#xdpyinfo
	make ensurevnc0running
	#DISPLAY=:0 java -cp ./target/fodselenium-0.0.1-SNAPSHOT-jar-with-dependencies.jar Tests.Login
	#sudo -u test1 env DISPLAY=:0 java -cp ./target/fodselenium-0.0.1-SNAPSHOT-jar-with-dependencies.jar Tests.Login
	#sudo -u test1 env DISPLAY=:0 java -cp ./target/fodselenium-0.0.1-SNAPSHOT-jar-with-dependencies.jar "Tests.$(CLASS1)"
	make mvntest1

full1: clean package1 run1
	@true

