<?php
namespace Application\Boostrap;

defined('C5_EXECUTE') or die("Access Denied.");

/********************************************************************************/
/***************************** IMPORTANT! READ ME *******************************/
/********************************************************************************/
/* Please replace the string YourPasswordHere below with your security password */
/****** Use only uppercase and lowercase letters and numbers and NO spaces ******/
/************ Make sure you keep both quotation marks " " around it *************/
/**** FOR SAFETY REASONS YOU MUST SET YOUR OWN PASSWORD OR IT WILL NOT WORK *****/
/********************************************************************************/

$authorizationPassword = "YourPasswordHere";

/********************************************************************************/
/********************************************************************************/
/*** DO NOT MODIFY ANYTHING BELOW THIS LINE UNLESS YOU KNOW WHAT YOU'RE DOING ***/
/********************************************************************************/
/********************************************************************************/

use Hautelook\Phpass\PasswordHash;
use Concrete\Core\Http\Request;
use Concrete\Core\Controller\Controller;
use Concrete\Core\Database\Connection\Connection;
use Concrete\Core\Support\Facade\UserInfo;
use Concrete\Core\Support\Facade\Application;
use Concrete\Core\Support\Facade\Url as URL;
use Exception;

if (!is_object($app)) {
    $app = Application::getFacadeApplication();
}

$request = $app->make(Request::class);

// get the security password and ensure it only contains letters and numbers
$pass = $app->make('helper/text')->alphanum((string) $request->request('p'));
$pass = trim($pass);

// check we have the correct password or exit
if (empty($pass)
    || $pass !== $authorizationPassword
    || md5($pass) !== md5($authorizationPassword)
    || md5($pass) === md5("YourPasswordHere")
) {
    return false;
}

class Recovery extends Controller
{
    protected $request;
    private $db;
    private $password;
    private $passwordConfirm;
    private $email;
    private $username;
    private $user = false;
    private $task;
    private $pass;
    private $token;
    private $config;
    private $ip;
    private $vals;
    private $valc;
    private $th;
    private $pv;
    private $rh;
    private $err;

    public function __construct(Request $request, $app, $pass = null)
    {
        $this->request = $request;
        $this->password = trim((string) $this->request->request('uPassword'));
        $this->passwordConfirm = trim((string) $this->request->request('uPasswordConfirm'));
        $this->email = trim((string) $this->request->request('uEmail'));
        $this->username = trim((string) $this->request->request('uName'));
        $this->username = preg_replace('/ +/', ' ', $this->username);
        $this->task = (string) $this->request->request('task');
        $this->pass = (string) $this->request->request('p');
        $this->token = (string) $this->request->request('ccm_token');

        $this->db = $app->make('database')->connection();
        $this->config = $app->make('config');
        $this->ip = $app->make('helper/validation/ip');
        $this->vals = $app->make('helper/validation/strings');
        $this->valc = $app->make('helper/concrete/validation');
        $this->th = $app->make('token');
        $this->pv = $app->make('validator/password');
        $this->rh = $app->make('user/registration');
        $this->err = $app->make('error');
    }

    public function getUserName()
    {
        return $this->username;
    }

    public function getUserEmail()
    {
        return $this->email;
    }

    public function getUser()
    {
        return $this->user;
    }

    private function validate()
    {
        if (version_compare(APP_VERSION, '8.0', '<')) {
                throw new Exception(t('This Super User Recovery tool only works with Concrete5 version 8 and above, sorry. For a tool that will work for your version of Concrete5, you can check %sConcrete5 LockPick%s', '<a href="https://github.com/mkly/concrete5-Lockpick" title="Get Concrete5 Lockpick on Github.">', '</a>'));
        }

        if (empty($this->task) || empty($this->pass) || empty($this->token)) {
            $this->err->add("Something was not right, please try again.");
        }

        if (!$this->th->validate($this->task . $this->pass, $this->token)) {
            $this->err->add("Invalid token, please try again.");
        }

        if ($this->ip->isBlacklisted()) {
            $this->err->add($this->ip->getErrorMessage());
        }

        if (empty($this->password) || empty($this->passwordConfirm)) {
            $this->err->add('You must provide both a password and a password confirmation. Please try again.');
        }

        if ($this->password !== $this->passwordConfirm) {
            $this->err->add("Password and password confirmation didn't match. Try again.");
        }

        $this->pv->isValid($this->password, $this->err);

        if ($this->task === "create_super_user" && empty($this->email)) {
            $this->err->add('An email address is required. Please provide one.');
        }

        if (!empty($this->email)) {
            if (!$this->vals->email($this->email)) {
                $this->err->add('Invalid email address provided.');
            } elseif (!$this->valc->isUniqueEmail($this->email)) {
                $this->err->add(t('The email address %s is already in use. Please choose another.', $this->email));
            }
        }

        if (!empty($this->username)) {
            if (strlen($this->username) < $this->config->get('concrete.user.username.minimum')) {
                $this->err->add(
                    t(
                        'A username must be at least %s characters long.',
                        $this->config->get('concrete.user.username.minimum')
                    )
                );
            }

            if (strlen($this->username) > $this->config->get('concrete.user.username.maximum')) {
                $this->err->add(
                    t(
                        'A username cannot be more than %s characters long.',
                        $this->config->get('concrete.user.username.maximum')
                    )
                );
            }

            if (!$this->valc->username($this->username)) {
                if ($this->config->get('concrete.user.username.allow_spaces')) {
                    $this->err->add(
                        t('A username may only contain letters, numbers, spaces, dots (periods), and underscore characters. Spaces, dots, and underscore characters cannot be at the beginning or end of the username.')
                    );
                } else {
                    $this->err->add(
                        t('A username may only contain letters, numbers, dots (periods), and underscore characters. Dots, and underscore characters cannot be at the beginning or end of the username.')
                    );
                }
            }
            if (!$this->valc->isUniqueUsername($this->username)) {
                $this->err->add(t('The username %s already exists. Please choose another', $this->username));
            }
        }

        if ($this->err->has()) {
            throw new Exception((string) $this->err);
        }
    }

    public function processRequest()
    {
        // let's check we're dealing with C5 8 and above and we have the information we need
        $this->validate();

        if ($this->task === 'update_super_user') {
            $result = $this->updateUser();
        } elseif ($this->task === 'create_super_user') {
            $result = $this->createUser();
        }

        // if password reset hash values are still in the DB for the Super User
        // They could be used by a third party to take control back
        // Let's delete them
        $this->removeHashes();

        return $result;
    }

    private function removeHashes()
    {
        $sql = 'DELETE FROM UserValidationHashes WHERE uID=?';
        $this->db->executeQuery($sql, [USER_SUPER_ID]);
    }

    private function updateUser()
    {
        $ui = UserInfo::getByID(USER_SUPER_ID);
        if (!is_object($ui) || $ui->getUserID() !== USER_SUPER_ID) {
            throw new Exception("That user doesn't exist, sorry.");
        }

        if (empty($this->email) && empty($this->username)) {
            // only changing the password
            $result = $ui->changePassword($this->password);
        } else {
            // changing the password and optionally the username and email
            $uData = [
                        'uPassword' => $this->password,
                        'uPasswordConfirm' => $this->passwordConfirm,
                    ];
            if (!empty($this->email)) {
                $uData['uEmail'] = $this->email;
            }
            if (!empty($this->username)) {
                $uData['uName'] = $this->username;
            }
            $result = $ui->update($uData);
        }

        if ($result) {
            return ['success' => t("Your Super User has been successfully modified. You can now %slog-in with your new password%s.", sprintf('<a href="%s" title="%s">', URL::to('/login'), t("Log-in as Super User")), '</a>')];
        } else {
            throw new Exception("Something went wrong and your Super User could not be updated.");
        }
    }

    private function createUser()
    {
        $hasher = new PasswordHash(
            $this->config->get('concrete.user.password.hash_cost_log2'),
            $this->config->get('concrete.user.password.hash_portable')
        );

        $uPasswordEncrypted = $hasher->HashPassword($this->password);

        $superUserCreated = $this->rh->createSuperUser($uPasswordEncrypted, $this->email);

        if ($superUserCreated) {
            // In theory the function createSuperUser() used above should create the user with an ID of USER_SUPER_ID
            // However that only works when installing Concrete5 and no other user has ever been created
            // After that user IDs (because they are automatically generated) use the next available number
            // This is why we have to update the number directly in the DB after the user is created
            $vals = [];
            $vals[] = USER_SUPER_ID;
            $sql = 'update Users set uID = ?';
            if (!empty($this->username)) {
                $vals[] = $this->username;
                $sql .= ', uName = ?';
            }
            array_push($vals, $superUserCreated->getUserID(), $this->email);
            $sql .= ' where uID = ? AND uEmail = ? limit 1';

            $this->db->executeQuery($sql, $vals);

            $this->user = UserInfo::getByID(USER_SUPER_ID);

            return ['success' => t("Your Super User has been successfully created. You can now %slog-in with your new credentials%s.", sprintf('<a href="%s" title="%s">', URL::to('/login'), t("Log-in as Super User")), '</a>')];
        } else {
            throw new Exception('Something went wrong and your Super User could not be created.');
        }
    }
}

// We got here becase the security password provided was correct
$error = false;
$success = false;
$uEmail = false;
$uName = false;
$task = (string) $request->request('task');
$submit = (string) $request->request('submit');
$taskManager = new Recovery($request, $app);

try {
    // the form was submitted so let's process
    if (!empty($submit)) {
        $result = $taskManager->processRequest();
        $success = $result['success'];
    }
} catch (Exception $ex) {
    $error = $ex->getMessage();
}

// We're loading the rest of the page so let's check what's going on with the Super User
$superuser = $taskManager->getUser();
$superuser = !$superuser ? UserInfo::getByID(USER_SUPER_ID) : $superuser;

if (is_object($superuser) && $superuser->getUserID() === USER_SUPER_ID) {
    $uEmail = $taskManager->getUserEmail();
    $uEmail = empty($uEmail) ? $superuser->getUserEmail() : $uEmail;
    $uName = $taskManager->getUserName();
    $uName = empty($uName) ? $superuser->getUserName() : $uName;
    $task = 'update_super_user';
    $startingMsg = t("%sGood News! You do have a Super User so you can just change its password and optionally its email and username and go on your merry way. So far we have:%s%s", '<p><strong>', '</p></strong>', sprintf('<ul><li>%s</li><li>%s</li></ul>', t("%sUsername:%s %s", '<strong>', '</strong>', $uName), t("%sEmail:%s %s", '<strong>', '</strong>', $uEmail)));
} else {
    $admin = UserInfo::getByUserName(USER_SUPER);
    $adminMsg = '';
    if (is_object($admin) && $admin->getUserName() === USER_SUPER) {
        $adminMsg = t("%sThe Username %s however is already in use. Make sure to specify another one and you can delete or modify stuff after you get your Super User back.%s", '<p style="color: #E7002E">', '"' . USER_SUPER . '"', '</p>');
    }
    $task = 'create_super_user';
    $startingMsg = t("%sIt seems the Super User has been deleted. Let's create a new one.%s%s", '<strong><p>', '</p>', $adminMsg . '</strong>');
}

// from here we're generating the page and the form
ob_start();
?>

<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="content-type" content="text/html; charset=utf-8" />
        <meta name="robots" content="noindex" />
        <meta name="viewport" content="initial-scale=1">

        <title><?php echo t("Concrete5 Super User Recovery") ?></title>
        <style type="text/css" media="all">
            body {
                color: #333;
                font-size: 14px;
                line-height: 1.5;
                margin: 0;
                padding: 0;
            }
            a,
            a:link,
            a:visited,
            a:hover,
            a:active {
                color: #34a5f8;
                font-weight: bold;
                text-decoration: none;
                border-bottom: 1px dotted #34a5f8;
            }
            a:hover,
            a:active {
                border-bottom: 1px solid #34a5f8;
            }
            a:active {
                padding: 1px 0px 0px 1px;
            }

            label,
            input,
            form,
            img {
                display: block;
            }
            .wrapper {
                display: block;
                padding: 15px;
            }
            form,
            .change-message {
                width: 250px;
                padding: 20px;
                -webkit-box-shadow: 0px 0px 3px 0px rgba(51, 51, 51, 0.3);
                box-shadow: 0px 0px 3px 0px rgba(51, 51, 51, 0.3);
            }
            img,
            form,
            .change-message {
                margin: 10px auto;
                text-align: center;
                font-weight: bold;
            }
            .change-message ul {
                text-align: left;
            }
            .change-message .delete-now {
                padding: 10px;
                color: #fff;
                background-color: rgba(0, 165, 0, 0.80);
                -webkit-box-shadow: 0px 0px 3px 0px rgba(51, 51, 51, 0.3);
                box-shadow: 0px 0px 3px 0px rgba(51, 51, 51, 0.3);

            }
            .change-message.error {
                color: #fff;
                background-color: rgba(231, 0, 46, 0.85);
            }
            .change-message.error a {
                background-color: #fff;
            }
            .change-message.success {
                color: #005711;
                background-color: rgba(0, 255, 0, 0.55);
            }
            .change-message li {
                margin-bottom: 10px;
            }
            input[type=text],
            input[type=password] {
                width: 240px;
                padding: 3px;
                font-size: 20px;
                background: #fff;
                border: 1px solid #999;
                margin-bottom: 4px;
            }
            input[type=text]:focus,
            input[type=password]:focus {
                border: 1px solid #20bde8;
            }
            input[type=submit] {
                float: right;
                margin: 7px;
                border: 1px solid #2370A8;
                background: -webkit-linear-gradient(#34a5f8, #088ef0);
                background: linear-gradient(#34a5f8, #088ef0);
                padding: 5px;
                color: #fff;
                -webkit-border-radius: 3px;
                -moz-border-radius: 3px;
                border-radius: 3px;
            }
            input[type=submit]:hover {
                -webkit-box-shadow: 0 0 5px 0 rgba(0,0,0,0.25);
                box-shadow: 0 0 5px 0 rgba(0,0,0,0.25);
            }
            input[type=submit]:active {
                padding: 6px 4px 4px 6px;
                background: #088ef0;
            }
            label {
                font-weight: bold;
            }
            .help-block {
                font-size: 87%;
                line-height: 1.2;
                color: #888;
                display: block;
                margin-top: 5px;
                margin-bottom: 10px;
            }
            .required {
                font-size: 87%;
                color: #777;
            }
            .header-kalmoya {
                margin-bottom: 30px;
                padding: 15px 15px 25px;
                border-color: #088ef0;
                background: -webkit-linear-gradient(#34a5f8, #088ef0);
                background: linear-gradient(#34a5f8, #088ef0);
                -webkit-box-shadow: 0 0 15px 0 rgba(0,0,0,0.25);
                box-shadow: 0 0 15px 0 rgba(0,0,0,0.25);
                text-align: center;
            }
            .built-by {
                font-family: Arial, sans-serif;
            }
            .kalmoya-logo,
            .kalmoya-logo svg {
                display: block;
                clear: both;
                height: 54px;
                width: 300px;
                border-bottom: none!important;
            }
            .creator-kalmoya {
                font-size: 16px;
                color: #fff;
                display: inline-block;
            }
            .creator-kalmoya em {
                font-family: serif;
            }
            .creator-kalmoya span.creator-sub-title {
                color: #ffffff;
                font-family: Arial, sans-serif;
                text-shadow: 0 0 15px rgba(0,0,0,0.35);
                margin-top: 5px;
                display: block;
                font-size: 80%;
            }
        </style>
    </head>
    <body>
        <svg style="display: none;"><symbol viewBox="0 0 339.854 61.5" id="kalmoya-logo"><title><?php echo t("Kalmoya.com - Expert Concrete5 Development") ?></title><path fill="#F9AC1B" d="M45.213 49.06c-1.667 0-2.4-.732-2.4-2.4V3.46c0-1.666.733-2.4 2.4-2.4h10.333c1.667 0 2.4.734 2.4 2.4v15.334h2.667L67.48 3.26c.667-1.6 1.6-2.2 3.333-2.2H81.08c1.534 0 2.067.8 1.467 2.2l-6.8 15.534c5 .267 8.2 3.733 8.2 9.066v18.8c0 1.667-.733 2.4-2.4 2.4H71.28c-1.667 0-2.4-.733-2.4-2.4v-13c0-1.466-.734-2.267-2.133-2.267h-8.8V46.66c0 1.667-.733 2.4-2.4 2.4H45.213zm55.369 11.44h-9.8c-1.667 0-2.4-.733-2.4-2.4V40.5c0-2.667.802-6 2.6-10.667L96.785 14.7c.532-1.533 1.6-2.2 3.4-2.2h17.933c1.733 0 2.8.666 3.333 2.2l5.8 15.133c1.8 4.667 2.6 8 2.6 10.667v17.6c0 1.667-.733 2.4-2.4 2.4h-10.065c-1.8 0-2.6-.733-2.6-2.4v-9.333h-11.8V58.1c-.002 1.667-.736 2.4-2.403 2.4zm3.067-23.866h10.466L110.982 26.5c-.333-.8-.732-1.133-1.267-1.133h-1.667c-.532 0-.934.333-1.267 1.133l-3.13 10.134zM132.687 60.5c-1.667 0-2.4-.733-2.4-2.4V14.9c0-1.667.733-2.4 2.4-2.4h10.333c1.666 0 2.4.734 2.4 2.4v33h9.133V37.1c0-1.667.732-2.4 2.4-2.4h9.666c1.666 0 2.398.734 2.398 2.4v21c0 1.667-.732 2.4-2.4 2.4h-33.93z"/><path fill="#FFF" d="M171.855 60.5c-1.668 0-2.4-.733-2.4-2.4V14.9c0-1.667.732-2.4 2.4-2.4h10.732c1.4 0 2.267.534 3.068 2l6 10.867c.466.8.667 1.133 1.2 1.133h.6c.533 0 .733-.333 1.2-1.133l5.933-10.867c.8-1.466 1.667-2 3.066-2h10.8c1.667 0 2.4.734 2.4 2.4v43.2c0 1.667-.733 2.4-2.4 2.4h-10.266c-1.733 0-2.4-.733-2.4-2.4V34.633l-3.933 7.267c-.8 1.533-1.8 2.133-3.534 2.133h-2.666c-1.733 0-2.733-.6-3.534-2.133l-3.933-7.267V58.1c0 1.667-.733 2.4-2.4 2.4h-9.932zm66.17 1c-16.667 0-20.733-5.466-20.733-13.6V25.167c0-8.134 4.066-13.667 20.733-13.667 16.666 0 20.667 5.534 20.667 13.667V47.9c0 8.134-4.002 13.6-20.667 13.6zm0-12.866c4.867 0 5.6-1.333 5.6-3.133V27.568c0-1.733-.733-3.066-5.6-3.066-4.8 0-5.6 1.334-5.6 3.067V45.5c0 1.8.8 3.134 5.6 3.134zM274.26 60.5c-1.732 0-2.398-.733-2.398-2.4v-8.533l-10.2-13.667c-2.066-2.733-2.534-4.067-2.534-8.2V14.9c0-1.667.734-2.4 2.4-2.4h10.268c1.667 0 2.4.734 2.4 2.4v10.934c0 .933 0 1.866.6 2.8l3.065 4.8c.468.8.868 1.133 1.6 1.133h.668c.734 0 1.134-.333 1.6-1.133l3.068-4.8c.6-.934.6-1.867.6-2.8V14.9c0-1.667.733-2.4 2.4-2.4h9.933c1.666 0 2.398.734 2.398 2.4v12.8c0 4.133-.532 5.467-2.532 8.2l-10.133 13.733V58.1c0 1.667-.734 2.4-2.4 2.4H274.26zm36.33 0h-9.8c-1.667 0-2.4-.733-2.4-2.4V40.5c0-2.666.8-6 2.6-10.667l5.8-15.133c.533-1.533 1.6-2.2 3.4-2.2h17.933c1.734 0 2.8.667 3.332 2.2l5.8 15.133c1.802 4.667 2.6 8 2.6 10.667v17.6c0 1.667-.73 2.4-2.397 2.4H327.39c-1.8 0-2.602-.733-2.602-2.4v-9.332h-11.8V58.1c0 1.667-.732 2.4-2.4 2.4zm3.065-23.866h10.467L320.99 26.5c-.335-.8-.734-1.133-1.268-1.133h-1.666c-.534 0-.934.333-1.268 1.133l-3.133 10.134z"/><path fill="#F9980D" d="M2.04 41.57a3.411 3.411 0 0 1 3.413-3.41h23.873a3.41 3.41 0 0 1 3.41 3.41v12.79a3.41 3.41 0 0 1-3.41 3.412H5.453a3.411 3.411 0 0 1-3.413-3.41V41.57z"/><path fill="#FFC41F" d="M2.04 41.295c0-1.69 1.528-3.064 3.413-3.064h23.873c1.883 0 3.41 1.374 3.41 3.065v11.493c0 1.69-1.527 3.064-3.41 3.064H5.453c-1.885 0-3.413-1.372-3.413-3.064V41.295z"/><path fill="#A39F95" d="M37.283 50.774V27.47a1.706 1.706 0 0 1 3.41-.001v21.6h21.6c.94 0 1.706.763 1.706 1.704s-.766 1.706-1.705 1.706H38.99l-1.707-1.706z"/><path fill="#89847A" d="M37.283 30.878v19.896l1.706 1.706h1.704v-21.6a1.706 1.706 0 0 0-3.412-.002z"/><path fill="#89847A" d="M31.03 43.854c0-.392.32-.71.71-.71h6.444a.71.71 0 0 1 0 1.42H31.74a.709.709 0 0 1-.71-.71zm0 2.75a.71.71 0 0 1 .71-.71h6.444a.71.71 0 1 1 0 1.42H31.74a.711.711 0 0 1-.71-.71zm0 2.746c0-.393.32-.71.71-.71h6.444a.71.71 0 1 1 0 1.42H31.74a.71.71 0 0 1-.71-.71z"/><circle fill="#FFC41F" cx="27.833" cy="56.208" r="3.623"/><path fill="#FFA522" d="M27.833 59.832c-2 0-3.623-1.62-3.623-3.623s1.622-3.624 3.623-3.624"/><path fill="#10445A" d="M22.503 56.208c0-2.94 2.392-5.33 5.33-5.33s5.328 2.39 5.328 5.33c0 2.938-2.39 5.33-5.327 5.33s-5.33-2.392-5.33-5.33zm3.41 0a1.92 1.92 0 0 0 3.838 0c0-1.06-.857-1.918-1.917-1.918s-1.92.86-1.92 1.918z"/><circle fill="#FFC41F" cx="6.944" cy="56.208" r="3.624"/><path fill="#FFA522" d="M4.382 58.77a3.623 3.623 0 1 1 5.124-5.124"/><path fill="#10445A" d="M3.175 52.44a5.334 5.334 0 0 1 7.536 0 5.33 5.33 0 1 1-7.535 0zm2.41 2.412a1.927 1.927 0 0 0 0 2.714c.75.748 1.968.748 2.714 0a1.922 1.922 0 0 0 0-2.714 1.922 1.922 0 0 0-2.714 0z"/><path fill="#F9980D" d="M5.547 24.21v15.395c0 .94.766 1.705 1.705 1.705.94 0 1.706-.765 1.706-1.705v-13.69h7.772l5.963 5.963v6.78c0 .942.764 1.706 1.707 1.706.938 0 1.703-.765 1.703-1.706V35.29l3.722 3.722a1.703 1.703 0 0 0 2.41 0 1.701 1.701 0 0 0 0-2.41L18.646 23c-.32-.318-.756-.5-1.207-.5H7.252c-.94 0-1.705.767-1.705 1.707z"/><path fill="#F76D0F" d="M5.548 27.48v12.127a1.707 1.707 0 0 0 3.411 0V25.915h7.772l5.96 5.964v6.781a1.707 1.707 0 0 0 3.413 0v-3.37l3.72 3.722a1.7 1.7 0 0 0 1.897.342l-13.077-13.08a1.71 1.71 0 0 0-1.207-.5H7.252c-.94 0-1.705.763-1.704 1.705z"/><path fill="#F9980D" d="M1 37.564c0-.32.26-.578.578-.578H33.2c.32 0 .578.258.578.578v3.182c0 .32-.258.58-.577.58H1.58a.58.58 0 0 1-.578-.58v-3.182z"/><path fill="#F7AA0F" d="M1 37.565v1.122c0 .318.26.578.578.578H33.2c.32 0 .578-.26.578-.578v-1.122a.577.577 0 0 0-.577-.578H1.58a.578.578 0 0 0-.578.578z"/><path fill="#F9980D" d="M23.5 45.266c0-.118.096-.213.213-.213h2.202c.117 0 .214.095.214.213s-.098.213-.215.213h-2.202a.215.215 0 0 1-.214-.214zm0 1.35c0-.116.096-.213.213-.213h2.202c.117 0 .214.095.214.213s-.098.214-.215.214h-2.202a.215.215 0 0 1-.214-.214zm0 1.35c0-.117.096-.213.213-.213h2.202c.117 0 .214.096.214.213a.216.216 0 0 1-.215.213h-2.202a.216.216 0 0 1-.214-.214z"/></symbol></svg>

        <div class="header-kalmoya clearfix">
                <span class="creator-kalmoya is-block">
                    <strong class="built-by"><?php echo t('Concrete5 Super User Recovery') ?></strong><br />
                    <em><?php echo t('Built & Maintained by') ?></em>
                    <a  class="kalmoya-logo" href="https://kalmoya.com" target=_BLANK rel="noopener, noreferrer" title="Visit Kalmoya.com Concrete5 specialist">
                        <svg xmlns="http://www.w3.org/2000/svg">
                            <use xlink:href="#kalmoya-logo"></use>
                        </svg>
                        <span class="creator-sub-title"><?php echo t("Hiring a Concrete5 Specialist Shouldn't Feel") ?><br><?php echo t("Like Pulling Teeth") ?></span>
                    </a>
                </span>
        </div>
        <div class="wrapper">
        <?php
        if (!empty($task)) { ?>

            <div class="change-message">
                <?=$startingMsg?>
            </div>
            <?php
            if ($error) { ?>
                <div class="change-message error">
                    <p><?php echo $error ?></p>
                </div>
            <?php
            } elseif ($success) { ?>
                <div class="change-message success">
                    <p><?php echo $success ?></p>
                    <p class="delete-now"><?php echo t("Do NOT leave this file lying around on your server. Delete it NOW! and clean-up your app.php file.") ?></p>
                </div>
            <?php
            } ?>
            <form method="post" action="/">
                <label for="uName">Username</label>
                <input type="text" name="uName" />
                <?php
                if ($task === 'update_super_user') { ?>
                    <span class="help-block"><?php echo t("Leave this field empty if you do not wish to modify the existing Username.") ?></span>
                <?php
                } elseif ($task === 'create_super_user') { ?>
                    <span class="help-block"><?php echo t("Leave this field empty if you want to use the default %sadmin%s as Username.", "&ldquo;", "&rdquo;") ?></span>
                <?php
                } ?>
                <label for="uEmail">Email <?=($task === 'create_super_user') ? '<span class="required">(' . t("Required") . ')</span>' : ''; ?></label>
                <input type="text" name="uEmail" />
                <?php
                if ($task === 'update_super_user') { ?>
                    <span class="help-block"><?php echo t("Leave this field empty if you do not wish to modify the existing Email.") ?></span>
                <?php
                } ?>
                <label for="uPassword"><?php echo t("New Password") ?>&nbsp;<span class="required">(<?php echo t("Required") ?>)</span></label>
                <input type="password" name="uPassword" />
                <label for="uPasswordConfirm"><?php echo t("Confirm Password") ?>&nbsp;<span class="required">(<?php echo t("Required") ?>)</span></label>
                <input type="password" name="uPasswordConfirm" />
                <input type="hidden" name="task" value="<?=$task?>" />
                <input type="hidden" name="p" value="<?=$pass?>" />
                <?php
                $token = $app->make('Concrete\Core\Validation\CSRF\Token');
                $token->output($task . $pass);
                ?>
                <input type="submit" name="submit" value="<?=ucwords(str_replace('_', ' ', $task))?>&nbsp;&#187;" />
                <div style="clear:both"></div>
            </form>
            <script>
                document.forms[0].elements[0].focus();
            </script>
        <?php
        } ?>
        </div>
    </body>
</html>
<?php
ob_end_flush();
exit;
?>
