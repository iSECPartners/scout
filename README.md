# AWS Scout

## Description

_NOTE:_ Due to API changes, this software no longer works on modern AWS.
Please see [Scout2](https://github.com/iSECPartners/Scout2) for a modern
equivalent.

The scale and variety of Amazon Web Servers (AWS) has created a
constantly changing landscape. What was previously managed by enterprise IT
groups is now done through a variety of Amazon-based services, leaving many
questions concerning the risk and security of these environments unanswered.

Scout is a security tool that lets AWS administrators asses their environments
security posture. Using the AWS API, Scout gathers configuration data for
manual inspection or highlights high-risk areas automatically. Rather than
pouring through dozens of pages on the web, Scout supplies a clear view of the
attack surface automatically.

## Installation
To install Scout, simply grab the latest jar from the [downloads](https://github.com/iSECPartners/scout/downloads)
page. You may want to put it somewhere in your `$PATH` to make it easier to run.

## Running
Scout is packaged as an executable jar. To run it, type

    $ java -jar scout-0.9.5-standalone.jar

This will print a short message describing the commands Scout supports.

## Usage

    java -jar scout-0.9.5-standalone.jar ACTION [OPTIONS]

The `action` argument will be explained in detail for each action below. The -c
arguments specifies the credentials the tool will use to make requests to the
AWS API.

### Actions

#### `list-instances`
Output a list of every instance in your EC2 account, grouped by security
group, along with selected attributes of the instance.

#### `list-groups`
Output a list of every security group, broken down permission by permission.

#### `audit-groups`
Output a list of notable or dangerous security group permissions.
Permissions are rated as critical, warning, or info depending on the service
exposed and how much of the internet the service is exposed to (a /8 is more
"critical" than a /24). For more information regarding this rating algorithm,
consult the wiki.

#### `compare-groups`
Output the difference between what is configured in EC2 and the supplied
ruleset file.  Permissions marked "+" are configured in EC2 but missing from
the ruleset, while permissions marked "-" are missing from EC2 but defined in
the ruleset.

`compare-groups` requires that you specify a ruleset file for it to compare
against. Here's an example ruleset:

```clojure
(ruleset
  (group :websrv
         (permission :tcp [80] "0.0.0.0/0")
         (permission :tcp [443] "0.0.0.0/0")
         (permission :tcp [22] "134.82.0.0/16"))
  (group :appsrv
         (permission :tcp [8080 8083] :websrv)
         (permission :tcp [22] "134.82.0.0/16"))
  (group :dbsrv
         (permission :tcp [5432] :appsrv)
         (permission :tcp [22] "134.82.0.0/16")))
```

#### `list-policies`
Output a list of S3 bucket permissions, organized by policy.

#### `audit-policies`
Output a list of every bucket permission opening any resource to the public.
This may or may not be useful, depending on how S3 is used.

### Flags

#### `-c <file>`
A file containing the IAM credentials of the AWS account to audit, and, optionally
lists of ports to flag and/or ignore while auditing security groups.

The very least required to use Scout is a set of IAM credentials, which are supplied
in this sample:

```clojure
(config
  (iam-credentials "ACCESS KEY ID" "SECRET ACCESS KEY"))
```

Optionally, you can instruct Scout to flag certain ports and/or ignore certain ports while auditing,
which is done in this example:

```clojure
(config
  (iam-credentials "ACCESS KEY ID" "SECRET ACCESS KEY")
  (flag-ports 53 8080)
  (ignore-ports 80 443))
```

#### `-f <ruleset-file>`
The file containing the ruleset to compare against the security groups
configured in EC2.

## License
GPLv2: See LICENSE.txt.

