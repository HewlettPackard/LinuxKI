# Licensed under GPL v2 or later
#
# See https://docs.docker.com/install/ for information on how to install Docker.
#
# After installing LinuxKI, build the container image:
#   docker build \
#     --tag linuxki \
#     --build-arg http_proxy=$http_proxy \
#     --build-arg https_proxy=$https_proxy \
#     --build-arg HTTP_PROXY=$HTTP_PROXY \
#     --build-arg HTTPS_PROXY=$HTTPS_PROXY \
#     /opt/linuxki
#
# When generating the LinuxKI reports with kiall, add the -V option to enable
# visualisations in the reports when possible.
#
# After the LinuxKI reports have been generated, to see the results with the
# visualizations, from the directory with the analysis results, run:
#   docker run \
#     --detach \
#     --name linuxki \
#     --publish-all \
#     --rm \
#     --volume $PWD:/var/www/html/linuxki \
#     linuxki
#
#   port=$(docker inspect \
#     --format='{{(index (index .NetworkSettings.Ports "80/tcp") 0).HostPort}}' \
#     linuxki)
#   echo Server running on port $port
#
#   html_file=$(find . -iname 'kp.*.html')
#   [[ $(echo $html_file | wc --words) -ne 1 ]] && unset html_file
#   xdg-open http://localhost:$port/linuxki/$html_file
#
# When finished looking at the results, run:
#   docker stop linuxki

FROM centos:7
LABEL maintainer="Christopher Voltz <christopher@voltz.ws>"

RUN yum update -y
RUN yum install -y yum-utils
RUN yum install -y httpd mod_ssl
RUN yum install -y http://rpms.remirepo.net/enterprise/remi-release-7.rpm && \
  yum-config-manager --enable remi-php72 && \
  yum install -y php php-opcache
RUN yum install -y https://raw.githubusercontent.com/HewlettPackard/LinuxKI/master/rpms/linuxki-7.3-1.noarch.rpm
RUN yum clean all -y && rm -rf /var/cache/yum

RUN echo '<?php phpinfo(); ?>' > /var/www/html/info.php

EXPOSE 80
EXPOSE 443

CMD /usr/sbin/httpd -DFOREGROUND
