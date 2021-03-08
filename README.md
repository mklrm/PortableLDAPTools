# Portable LDAP Tools module for Powershell

***Note that this module is not finished, not everything is necessarily working properly and things might break. It is however approaching some sort of 1.0 stage where most of the current functionality shouldn't see massive changes.***

A collection of commands to help achieve basic tasks like finding and modifying objects on a directory service via the Lightweight Directory Access Protocol. I've only tested against Active Directory and things like which attributes are shown by default are very much picked with Active Directory in mind.

General usage pattern is to pass commands search terms that the command then uses to find objects such as user accounts by way of fuzzy matching, much like as Active Directory Users and Computers Find does.

You don't need New-Menu (https://github.com/mklrm/New-Menu) to use this module but it is what makes many of these commands *nice* to use. It is used to display interactive menus that allow the user to choose which objects to modify from the ones that are found.

The user is always asked to confirm whether to apply the requested changes to the found objects.

So it's designed for interactive use and not for being used in scripts. I am aware I'm doing some things here in a very non-powershell way.

Automatically logs changes to a file (under a subdirectory in My Documents on Windows or the home directory on Linux) and announces where to find it after each command.

## Installation

Clone New-Menu (optional but recommended):

    git clone https://github.com/mklrm/New-Menu

Then Portable LDAP Tools itself:

    git clone https://github.com/mklrm/PortableLDAPTools

Import the modules:

    Import-Module -Path ./New-Menu/New-Menu.psm1 -Force
    Import-Module -Path ./PortableLDAPTools/PortableLDAPTools.psm1 -Force

I wouldn't go installing either one quite yet even if it is possible (which I don't know if it is). I load them from my $PROFILE.

## Setup

Automatically asks for things like server name and port, username and password* and saves them to a config file when one of the commands is invoked.

*as a secure string so it should be relatively well protected. The password can be decrypted by the account that encrypted it on the machine it was encrypted on without passing any sort of secret but should not be able to be cracked within a timeframe that matters at least if you make a habit of changing your passwords regularly.

Allows multiple connection configurations to be stored.

Commands to juggle the connection configuration file are *New-LDAPConnectionConfiguration* which adds a new connection configuration, *Edit-LDAPConnectionConfiguration* does what it sounds like, *Set-LDAPConnectionConfigurationActive* sets a specific configuration as the one that gets loaded at module import. *Remove-LDAPConnectionConfiguration* removes a config.

Frankly going with making multiple configurations possible was *way* over doing things for what this module is or ever will be as it needlessly complicated things. Remember KISS. Basically, run a command, answer questions and you probably will not need to touch these again.

## Menu controls

Use *up and down arrow*, *page up and down* to move around, an *alphanumerical key* press jumps to the next item starting with that character and you can use *slash (/)* to search.

## Commands

I'll be listing aliases instead of the commands themselves as those would be what any sane person would be using.

You can get all aliases by running:

    Get-Alias LDAP*

You can run each command without passing any parameters to get a help text.

### LDAPGet

What you might do with LDAPGet for example:

    LDAPGet 'John Doe', 'Doe Jane'

LDAPGet will try to find you both no matter which order you write the names in. You could do:

    LDAPGet *Doe*

Mix and match the search terms as you please.

You can list Objects in an organizational unit by doing:

    LDAPGet contoso.com/organizational/unit/*

### LDAPGetBy

Finds objects by values in their attributes. To list objects with Doe in their cn:

    LDAPGetBy cn *Doe*

Can list all child objects in an organizational unit by passing something like:

    LDAPGetBy CanonicalName contoso.com/Users/*

or

    LDAPGetBy DistinguishedName '*,CN=Users,DC=contoso,DC=com'

### LDAPSet

Used to set object attribute values by doing something like the following:

    LDAPSet 'John Doe', 'Doe Jane' mail JohnAndJaneDoe@example.com

### LDAPAdd

Adds values to single and multi-value attributes, such as a new number to othermobile:

    LDAPAdd *Doe* othermobile 123321123

### LDAPRem

Removes values from single and multi-value attributes, such as a number from othermobile:

    LDAPRem *Doe* othermobile 123321123

### LDAPClr

Clears all values from single and multi-value attributes, such like:

    LDAPClr *Doe* othermobile

### LDAPAddMember

Perhaps one of the more useful commands, used to add members to groups:

    LDAPAddMember 'Group A', 'Group B' 'John Doe', 'Doe Jane'

### LDAPRemMember

Works similarly to LDAPAddMember but you can also do...

    LDAPRemMember 'Group A' *

...to get a list of all members in a group and choose to remove all of them from it or pick and choose which ones to remove.

### LDAPGetMemberRecursive

Lists group members recursively, so a command like:

    LDAPGetMemberRecursive group1

Will write something like:

group1 > member1
group1 > member2
group1 > group2
group1 > group2 > member3
group1 > group2 > group3
group1 > group2 > group3 > member4

...and so on and so forth. Still comtemplating what a more useful output would be.

### LDAPSetPass

Find accounts and set random passwords to them by doing:

    LDAPSetPass *Doe*

After confirmation of which objects to target the command will reset passwords and then at the end offer to either write them to a csv file with account information or to print on the command line. It will include the value of the mail attribute in the output but doesn't do anything fancier than that to get addresses right now.

### LDAPRemObj

Removes objects:

    LDAPRemObj 'John Doe', 'Doe Jane'

### LDAPMove

You could for example list objects in an organizational unit and the command will ask you to pick which ones to move and where:

    LDAPMove contoso.com/organizationalunit1/*

or just move Jane Doe:

    LDAPMove 'Jane Done'

### LDAPDisable

    LDAPDisable 'Doe Jane', 'John Doe'

### LDAPEnable 

    LDAPEnable 'John Doe', 'Doe Jane'

## Notes

### Linux compatibility

Unfortunately New-Menu in its current form is unlikely to ever be Linux compatible. The Linux version of pwsh doesn't implement methods it depends on and I highly doubt there's a way to get around that. New-Menu needs to pretty much be redone from scratch though as it's a mess. I didn't use actual classes so it would be compatible with ancient versions of Powerhell and it turned into spaghetti anyways as I kept adding features. Perhaps I could add some alternate, simpler mode that doesn't modify the buffer if I have the energy, interest and time to rewrite.

### Apple compatibility

I assume the situation to be much the same as with Linux.
