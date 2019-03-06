# Super User Complete Recovery Solution for Concrete5

This for Concrete5 v8 tool helps you recover your Concrete5 website's Super User account in (almost) any situation.

Concrete5's Super User is the only omnipotent user, the one that can't be limited in any way and has full authority over your website.

As such, not having full control of the Super User means your control over your own website can be limited.

Even worse, whoever else has control over your Super user can take your website hostage.

But before you try and use this tool to get your Super User back, please consider the following.

## Legitimate reason you might not have been given Super User Control

Whoever connects as the Super User has to know exactly what they are doing because **they have the power to destroy things irremediably**.

I know many web professionals who do NOT give their client the Super User credentials because they don't want them to break stuff.

**This is the only legitimate reason I know and can think of for not giving you Super User access.**
Although a legitimate reason, it is only acceptable if the web professional is ready to hand the Super User over to the site owner, at no extra cost, **provided the site owner understands the responsibility**.

Don't ask for control over the Super User, break stuff and then expect the developer to fix it for free or even blame them for the havoc you wreaked and the misery you brought upon yourself.

## Before you use this tool, did you try this?

**Concrete5 comes with a password recovery tool** you can access from your login screen. Did you try that? If not, try that first, it's easier.

## What can this tool do for you

This tool helps you **recover your Super User account** by **taking into account several possible scenarios** from the simplest (You lost your password) to the most serious (someone took steps to make sure you can't take control back of your Super User account)

**This tool can help you get your Super User back if:**

- you lost your password
- you lost your username/email and password
- you don't have access to your email
- the Super User username was changed from "admin" to something else and you don't know what it is
- the Super User account was deleted
- the Super User account was deleted and another user was given the "admin" username

In any case, the tool will **let you know exactly what the situation is** and will give you **all the information you need to fix it**.

## Requirements

There's only one requirement: **you must have access to your server and the files on your server**. Nothing else is required.

If you don't have access to your Super User AND no access to your server, I am afraid you're stuck.

## If you were the victim of foul play follow these steps first

If someone activaly tried to block your access to the Super User they can counter your attempt at getting it back if you do not follow this steps before and after recovering it.

### Before you start

You have to make sure nobody can **go back to your server and rollback your changes** after you recovered your Super User. They could even do it using this exact same tool.

Follow these steps:

1. Delete all user accounts that have access to your **hosting account** except your own
2. Change your own hosting account password
3. make sure your hosting account uses **your own email address**
4. Delete all existing FTP accounts
5. Create a new FTP account that **you and only you fully control**

### After you recovered your Super User

After you recovered your Super User and you followed the steps above, it is highly unlikely someone could steal it back from you but they still could break stuff on your site so follow these steps:

1. Delete all users in the "administrators" user group that you do not recognize or are not needed
1. Delete all users in any group with specific editing permissions if you do not recognize them or do not need them
1. Delete all users not in any group that you do not recognize or need and that seem to have specific editing permissions in place

## How to use this Super User Recovery Tool

**Download the file c5-su-recovery.php** and put it on your server inside `application/bootstrap`

Open the file for modification and, at the top, where it says

    $authorizationPassword = "YourPasswordHere";

Put your own security password in place of `YourPasswordHere` and save. **Your new password can only use numbers and letters and no spaces**. So if your new password is *mySafetyPassword*, you will have

    $authorizationPassword = "mySafetyPassword";

**This is not your new Super User password, it is only a security password to make sure others can't use this tool while you are working with it.**

**And please make it something better than "mySafetyPassword"!!!**

Open the file `application\bootstrap\app.php` for modification and, at the top, add the line

    require_once __DIR__ . '/c5-su-recovery.php';

Now you're ready to go. **Visit any page on your website by adding this at the end of the URL**:

    ?p=mySafetyPassword

If you visit your home page for instance you will use **https://www.yourwebsite.com?p=mySafetyPassword**

There you will be greeted by a form and an explanatory message describing your situation and the steps to follow. Just follow the steps.

## Extra better-safe-than-sorry steps after recovery

Once you done, I strongly suggest you delete the recovery tool from your server. To do so

1. Remove the code added to `application\bootstrap\app.php`
2. Delete the file c5-su-recovery.php
3. Login as the Super User and change your password again just to be sure
4. Remove any user accounts you don't need from your website
