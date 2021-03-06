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
"""
Internal graph-based implementation of Network Function Forwarding Graph
"""
from networkx.release import get_info, major as nx_major

# Enabled imports directly from nffg_lib package
from nffg import NFFG, NFFGToolBox

if int(nx_major) > 1:
  raise RuntimeError(
    "NetworkX version(<2.0): %s is not supported!" % get_info()[2])

__version__ = nffg.VERSION
__all__ = ["NFFG", "NFFGToolBox"]
