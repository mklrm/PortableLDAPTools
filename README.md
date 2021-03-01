# Portable LDAP Tools module for Powershell

# NOTE THAT THIS MODULE IS UNFINISHED, NOT EVERYTHING IS WORKING PROPERLY, THINGS MIGHT BREAK ETC.

A collection of commands to help achieve basic tasks like finding and modifying objects on a directory service via the Lightweight Directory Access Protocol. I've only tested against Active Directory and things like which attributes are shown by default are very much designed with Active Directory in mind.

Uses my New-Menu module to display interactive menus to allow choosing objects to modify.

Should mostly work on Linux too although I really haven't been testing it yet. New-Menu might not be at all compatible and thus disabled on Linux for now.

Designed for interactive use. I am aware I'm doing some things here in a very unpowershellish manner.

Automatically logs changes to a file in My Documents or home dir.

## Installation

**At your own risk.**

## Setup

Automatically asks for things like server name and port, username, password (you're allowed to skip this) and saves them to a config file.

Allows multiple connection configurations to be stored in the .xml file saved to My Documents or home dir.

## Usage

As this is supposed to be something you use to quickly and easily get things done on the command line I'll be using aliases in the examples.

When a command that modifies anything is run, a list of the changes that are about to be made will be displayed and the user is asked to confirm, cancel or modify the list of changes about to be committed. 

I won't be listing all of the commands, you can get the aliases by running:

    Get-Alias LDAP*

You can run each command without passing parameters to get help.

### LDAPGet

Will print the following without passing parameters:

    Looks for objects by search terms and returns either all or requested return attributes. Search is fuzzy, you pass keywords that can include '*' as wildcards and the script attempts to find objects that have those values in attributes that generally identify an object such as Name, sAMAccountName, UserPrincipalName and so forth. So keep in mind that you are not making exact searches which is why these commands first let you know what is about to be done and you then have to choose to apply the changes.

    Usage: LDAPGet SearchTerm(s)
    Usage: LDAPGet SearchTerm(s) ReturnAttribute(s)

         SearchTerm: Term to find objects by
    ReturnAttribute: Which attributes to return per object '*' which is the default, means any value other than null.

Other commands follow suit. So what you might do with LDAPGet for example:

    LDAPGet 'John Doe', 'Doe Jane'

LDAPGet will try to find you both no matter which order you write the names in. You could do:

    LDAPGet '*Doe*'

Mix and match the search terms as you please.

You can list the users in an organizational unit by doing:

    LDAPGet contoso.com/organizational/unit/*

### LDAPGetBy

Finds attributes by the value in a specific attribute. Can list all child objects in an organizational unit by passing something like:

    LDAPGetBy CanonicalName contoso.com/Users/*

or

    LDAPGetBy DistinguishedName '*,CN=Users,DC=contoso,DC=com'

### LDAPSet

Used to change object attribute values by doing something like the following:

    LDAPSet 'John Doe', 'Doe Jane' mail JohnAndJaneDoe@example.com

### LDAPAdd

Adds values to single and multi-value attributes.

### LDAPRem

Removes values from single and multi-value attributes.

### LDAPClr

Clears all values from single and multi-value attributes.

### LDAPAddMember

Perhaps one of the more useful commands, used to add members to groups:

    LDAPAddMember 'Group A', 'Group B' 'John Doe', 'Doe Jane'

### LDAPRemMember

Works similarly to LDAPAddMember but you can also do...

    LDAPRemMember 'Group A' *

...to get a list of all members in a group and choose to remove all of them from it or pick and choose which ones to remove.

### LDAPRemObj

    LDAPRemObj 'John Doe', 'Doe Jane'

### The rest

The rest of the commands already present are more or less waiting to grow into something worth using.
