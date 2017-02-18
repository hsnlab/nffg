# Copyright 2017 Janos Czentye, Balazs Nemeth, Balazs Sonkoly
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from setuptools import setup

from nffg import VERSION

MODULE_NAME = "nffg"

setup(name=MODULE_NAME,
      version=VERSION,
      description="Network Function Forwarding Graph",
      author="Janos Czentye, Balazs Nemeth, Balazs Sonkoly",
      long_description="Python-based implementation of "
                       "Network Function Forwarding Graph used by ESCAPE",
      classifiers=[
        'Development Status :: 4 - Beta',
        "Intended Audience :: Telecommunications Industry",
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2.7',
        'Topic :: Software Development :: Libraries :: Python Modules'
      ],
      keywords='networking NFV BiSBiS forwarding',
      url="http://sb.tmit.bme.hu/escape",
      author_email="{name}.{name}@tmit.bme.hu",
      maintainer="Janos Czentye",
      maintainer_email="czentye@tmit.bme.hu",
      license="Apache 2.0",
      install_requires=[
        "networkx>=1.11"
      ],
      package_dir={MODULE_NAME: "."},
      packages=[MODULE_NAME],
      scripts=["nffg_diff.py"],
      include_package_data=True,
      zip_safe=False)
