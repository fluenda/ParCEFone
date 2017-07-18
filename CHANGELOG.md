<!--

 (C) Copyright 2016 Fluenda.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

-->

# 1.2.5
## Improvements
* [PERFORMANCE] Allow the reuse of Bean Validator
* Reduce dependencies 

# 1.2.3 & 1.2.4
## Bug Fixes
* Fix typos on CEF extension keys

# 1.2.2
## Bug Fixes
* Adjusts timeRegex match to match non-ASCII characters

# 1.2.1
## Improvements
* Allow developers to control the locale used when parsing Date 
  extensions (defaulting to Locale.ENGLISH for backward compatibility)
* Improve documentation
## Bug Fixes
* ParCEFone Data parsing was locale dependent

# 1.2.0
## Improvements
* Dependency version bump and adoption of semantic versioning (no further 
  beaking changes to be introduced in minor versions)

# 1.1.1
## Bug Fixes
* Fixes IndexOutOfBoundsException when Parser is fed with totally bogus 
  input

# 1.1 
## Improvements
* Cover all 9 possible timestamp formats decribed in Appendix A

## Major changes
* All date related fields are now Date objects (breaking)
* getExtensions has been renamed to getExtension (breaking)

## Bug Fixes
* Properly handle float and double fields

# 1.0

The wild west...
