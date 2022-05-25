<?php

namespace Tiger;

use RudyMas\Manipulator\Text;
use RudyMas\DBconnect;
use Sonata\GoogleAuthenticator\GoogleAuthenticator;
use Sonata\GoogleAuthenticator\GoogleQrUrl;

/**
 * Class Login (Version PHP 7.4)
 *
 * In the MySQL table 'tiger_users' you only need to add 6 fixed fields:
 * - id             = int(11)       : Is the index for the table (auto_increment)
 * - username       = varchar(40)   : The login username
 * - email          = varchar(70)   : The login e-mail
 * - password       = varchar(255)  : The login password (Hashed with SHA256)
 * - salt           = varchar(32)   : Used for extra security
 * - remember_me    = varchar(40)   : Special password to automatically login
 * - remember_me_ip = varchar(45)   : The IP from where the user can log in automatically
 *                                      (Can be an IPv4 or IPv6 address)
 * - access_level   = int(2)        : This can be used to set up levels of access to the website
 * - 2FA_active     = tinyint(1)    : Boolean to indicate if 2FA is active or not (Default = 0)
 * - 2FA_key        = varchar(16)   : The key used for the 2FA
 * - 2FA_token      = varchar(32)   : Token to check if user has successfully logged in with 2FA
 *
 * For security purposes, the users will only be able to automatically log in as long as they are working with the same
 * IP-address. If the IP-address changes, the user needs to log in again.
 *
 * You can add other fields to the table, and these can be accessed through ->getData(<key>)
 * and changed by ->setData(<key>, <value>)
 *
 * @author Rudy Mas <rudy.mas@rmsoft.be>
 * @copyright 2022, rmsoft.be. (https://www.rmsoft.be/)
 * @license https://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * @version 7.4.1.0
 * @package Tiger
 */
class Login
{
    public int $errorCode;
    private DBconnect $db;
    private Text $text;
    private bool $emailLogin;
    private GoogleAuthenticator $googleAuth;
    private array $data = [];

    /**
     * Login constructor.
     * @param DBconnect $dbConnect
     * @param Text $text
     * @param bool $emailLogin
     */
    public function __construct(DBconnect $dbConnect, Text $text, bool $emailLogin = false)
    {
        $this->db = $dbConnect;
        $this->text = $text;
        $this->emailLogin = $emailLogin;
        $this->googleAuth = new GoogleAuthenticator();
    }

    /**
     * @param bool $cookie
     */
    public function logoutUser(bool $cookie = false): void
    {
        unset($_SESSION['password']);
        unset($_SESSION['IP']);
        $this->data = [];
        setcookie('remember_me', '', -1, '/');
        if ($cookie) {
            setcookie('login', '', -1, '/');
        }
    }

    /**
     * @param string $userLogin
     * @param string $password
     * @param bool $remember
     * @return bool
     */
    public function loginUser(string $userLogin, string $password, bool $remember = false): bool
    {
        $query = "SELECT *
                  FROM tiger_users
                  WHERE username = {$this->db->cleanSQL($userLogin)}";
        if ($this->emailLogin) {
            $query .= " OR email = {$this->db->cleanSQL($userLogin)}";
        }
        $this->db->query($query);
        if ($this->db->rows != 0) {
            $this->db->fetchRow(0);
            if (password_verify($password . $this->db->data['salt'], $this->db->data['password'])) {
                setcookie('login', $userLogin, time() + (30 * 24 * 3600), '/');
                if ($remember) {
                    $this->data['remember_me'] = $this->text->randomText(40);
                    $this->data['remember_me_ip'] = $this->fetchIP();
                    $this->updateUser($userLogin);
                    setcookie('remember_me', $this->data['remember_me'], time() + (30 * 24 * 3600), '/');
                } else {
                    $_SESSION['password'] = base64_encode($password . $this->db->data['salt']);
                    $_SESSION['IP'] = $this->fetchIP();
                }
                $this->translateData();
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * @return bool
     */
    public function checkUser(): bool
    {
        $remember = false;
        $IP = '';
        $password = '';
        $userLogin = $_COOKIE['login'] ?? '';
        if (isset($_COOKIE['remember_me'])) {
            $password = $_COOKIE['remember_me'];
            $remember = true;
        } elseif (isset($_SESSION['password']) && isset($_SESSION['IP'])) {
            $password = base64_decode($_SESSION['password']);
            $IP = $_SESSION['IP'];
        }
        if ($userLogin != '' && $password != '') {
            $query = "SELECT * 
                      FROM tiger_users
                      WHERE username = {$this->db->cleanSQL($userLogin)}";
            if ($this->emailLogin) {
                $query .= " OR email = {$this->db->cleanSQL($userLogin)}";
            }
            $this->db->query($query);
            if ($this->db->rows != 0) {
                $this->db->fetchRow(0);
                if (($remember) ? $password == $this->db->data['remember_me'] : password_verify(
                    $password,
                    $this->db->data['password']
                )) {
                    if ($remember) {
                        $IP = $this->db->data['remember_me_ip'];
                    }
                    if ($IP == ($fetchIP = $this->fetchIP())) {
                        if (password_needs_rehash($this->db->data['password'], PASSWORD_BCRYPT)) {
                            $this->db->data['password'] = password_hash($password, PASSWORD_BCRYPT);
                            $this->translateData();
                            $this->updateUser();
                        } else {
                            $this->translateData();
                        }
                        return true;
                    } else {
                        if (filter_var($IP, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) == filter_var(
                            $fetchIP,
                            FILTER_VALIDATE_IP,
                            FILTER_FLAG_IPV6
                        )) {
                            $this->logoutUser();
                            ?>
                            <script type="text/javascript">
                                alert('You have been logged out by the system and need to login again.');
                            </script>
                            <?php
                            return false;
                        } else {
                            if (password_needs_rehash($this->db->data['password'], PASSWORD_BCRYPT)) {
                                $this->db->data['password'] = password_hash($password, PASSWORD_BCRYPT);
                                $this->translateData();
                                $this->updateUser();
                            } else {
                                $this->translateData();
                            }
                            return true;
                        }
                    }
                } else {
                    $this->logoutUser();
                    return false;
                }
            } else {
                $this->logoutUser();
                return false;
            }
        } else {
            $this->logoutUser();
            return false;
        }
    }

    /**
     * @return bool
     */
    public function insertUser(): bool
    {
        $nameField = [];
        if (!isset($this->data['username'])) {
            $this->data['username'] = 'Not Used';
        }
        if (!isset($this->data['email'])) {
            $this->data['email'] = 'No Email Address';
        }
        $this->data['salt'] = $this->text->randomText(32);
        $this->data['remember_me'] = '';
        $this->data['remember_me_ip'] = '';
        if (!isset($this->data['access_level'])) {
            $this->data['access_level'] = '99';
        }

        $query = "SELECT id FROM tiger_users";
        if ($this->emailLogin) {
            $query .= " WHERE email = {$this->db->cleanSQL($this->data['email'])}";
        } else {
            $query .= " WHERE username = {$this->db->cleanSQL($this->data['username'])}";
        }
        $this->db->query($query);
        if ($this->db->rows != 0) {
            $this->errorCode = 9;
            return false;
        }

        $query = "SELECT COLUMN_NAME AS 'field'
                  FROM INFORMATION_SCHEMA.COLUMNS
                  WHERE TABLE_NAME = 'tiger_users'
                    AND TABLE_SCHEMA = (SELECT DATABASE())";
        $this->db->query($query);
        $numberOfFields = $this->db->rows;
        for ($x = 0; $x < $numberOfFields; $x++) {
            $this->db->fetchRow($x);
            $nameField[$x] = $this->db->data['field'];
        }

        $query = "INSERT INTO tiger_users (";
        $query .= $nameField[1];
        for ($x = 2; $x < $numberOfFields; $x++) {
            $query .= ", ";
            $query .= $nameField[$x];
        }
        $query .= ") VALUES (";
        if (!isset($this->data[$nameField[1]])) {
            $this->data[$nameField[1]] = '';
        }
        $query .= $this->db->cleanSQL($this->data[$nameField[1]]);
        for ($x = 2; $x < $numberOfFields; $x++) {
            $query .= ", ";
            if ($nameField[$x] == 'password') {
                $password = password_hash($this->data['password'] . $this->data['salt'], PASSWORD_BCRYPT);
                $query .= $this->db->cleanSQL($password);
            } else {
                if (!isset($this->data[$nameField[$x]])) {
                    $this->data[$nameField[$x]] = '';
                }
                $query .= $this->db->cleanSQL($this->data[$nameField[$x]]);
            }
        }
        $query .= ")";
        $this->db->insert($query);

        if ($this->emailLogin) {
            $loginResult = $this->loginUser($this->data['email'], $this->data['password']);
        } else {
            $loginResult = $this->loginUser($this->data['username'], $this->data['password']);
        }
        if ($loginResult) {
            return true;
        } else {
            $this->errorCode = 2;
            return false;
        }
    }

    /**
     * @param string $user
     * @return bool
     */
    public function updateUser(string $user = ''): bool
    {
        if ($user != '') {
            $userLogin = $user;
        } elseif (isset($_COOKIE['login'])) {
            $userLogin = $_COOKIE['login'];
        } else {
            return false;
        }
        $query = "UPDATE tiger_users SET ";
        foreach ($this->data as $key => $value) {
            if ($key != 'id') {
                $query .= "{$key} = {$this->db->cleanSQL($value)},";
            }
        }
        $query = rtrim($query, ',');
        if ($this->emailLogin) {
            $query .= " WHERE email = {$this->db->cleanSQL($userLogin)}";
        } else {
            $query .= " WHERE username = {$this->db->cleanSQL($userLogin)}";
        }
        $this->db->update($query);
        return true;
    }

    /**
     * @param string $oldPassword
     * @param string $newPassword
     * @return bool
     */
    public function updatePassword(string $oldPassword, string $newPassword): bool
    {
        if (password_verify($oldPassword . $this->data['salt'], $this->data['password'])) {
            $this->data['salt'] = $this->text->randomText(32);
            $this->data['password'] = password_hash($newPassword . $this->data['salt'], PASSWORD_BCRYPT);
            if ($this->emailLogin) {
                $this->updateUser($this->data['email']);
            } else {
                $this->updateUser($this->data['username']);
            }
            return true;
        } else {
            return false;
        }
    }

    /**
     * @param string $login
     * @return mixed
     */
    public function resetPassword(string $login)
    {
        $query = "SELECT * FROM tiger_users";
        if ($this->emailLogin) {
            $query .= " WHERE Email = {$this->db->cleanSQL($login)}";
        } else {
            $query .= " WHERE username = {$this->db->cleanSQL($login)}";
        }
        $this->db->queryRow($query);
        if ($this->db->rows == 0) {
            return false;
        }
        $this->translateData();
        $output = $this->data['remember_me'] = $this->text->randomText(15);
        $this->updateUser($login);
        $this->logoutUser();
        return $output;
    }

    /**
     * @param string $remember_me
     * @param string $password
     */
    public function createNewPassword(string $remember_me, string $password): void
    {
        $query = "SELECT *
                  FROM tiger_users
                  WHERE remember_me = {$this->db->cleanSQL($remember_me)}";
        $this->db->queryRow($query);
        $this->translateData();
        $this->data['salt'] = $this->text->randomText(32);
        $this->data['password'] = password_hash($password . $this->data['salt'], PASSWORD_BCRYPT);
        $this->data['remember_me'] = '';
        if ($this->emailLogin) {
            $this->updateUser($this->data['email']);
        } else {
            $this->updateUser($this->data['username']);
        }
    }

    /**
     * Creating the QR-code for Google 2FA
     *
     * @param string $userEmail
     * @param string $secret
     * @param string $issuer
     * @return string
     */
    public function create2faQrUrl(string $userEmail, string $secret, string $issuer): string
    {
        return GoogleQrUrl::generate($userEmail, $secret, $issuer);
    }

    /**
     * Check if the supplied code is correct
     *
     * @param string $secret
     * @param string $code
     * @return bool
     */
    public function check2faCode(string $secret, string $code): bool
    {
        return $this->googleAuth->checkCode($secret, $code);
    }

    /**
     * Create secret key
     *
     * @return string
     */
    public function create2faSecret(): string
    {
        return $this->googleAuth->generateSecret();
    }

    /**
     * @return string
     */
    private function fetchIP(): string
    {
        if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)) {
            $addresses = explode(', ', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $IP = $addresses[count($addresses) - 1];
        } elseif (array_key_exists('REMOTE_ADDR', $_SERVER)) {
            $IP = $_SERVER['REMOTE_ADDR'];
        } elseif (array_key_exists('HTTP_CLIENT_IP', $_SERVER)) {
            $IP = $_SERVER['HTTP_CLIENT_IP'];
        } else {
            $IP = 'Unknown';
        }
        if (preg_match('/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]*/', $IP)) {
            $temp = explode(':', $IP);
            $IP = $temp[0];
        }
        return $IP;
    }

    /**
     * Transform clean SQL data to normal data
     */
    private function translateData(): void
    {
        foreach ($this->db->data as $key => $value) {
            $this->data[$key] = $value;
        }
    }

    /**
     * Setting the username
     *
     * @param string $username
     */
    public function setUsername(string $username): void
    {
        $this->data['username'] = $username;
    }

    /**
     * Setting the e-mail address
     *
     * @param string $email
     */
    public function setEmail(string $email): void
    {
        $this->data['email'] = $email;
    }

    /**
     * Setting the password
     * Can only be used when creating a new user
     * Changing the password of an existing user has to be done thought the function updatePassword()
     *
     * @param string $password
     */
    public function setPassword(string $password): void
    {
        $this->data['password'] = $password;
    }

    /**
     * Setting the access_level of the user
     * This van be a number from 0 to 99
     *
     * @param int $accessLevel
     */
    public function setAccessLevel(int $accessLevel): void
    {
        $this->data['access_level'] = $accessLevel;
    }

    /**
     * Setting if 2FA is active or not
     *
     * @param bool $active
     */
    public function set2faActive(bool $active): void
    {
        $this->data['2FA_active'] = $active;
    }

    /**
     * Setting the key for 2FA
     *
     * @param string $key
     */
    public function set2faKey(string $key): void
    {
        $this->data['2FA_key'] = $key;
    }

    /**
     * Setting a new token for 2FA
     *
     * @return string
     */
    public function set2faToken(): string
    {
        return $this->data['2FA_token'] = $this->text->randomText(32);
    }

    /**
     * Get user's id
     *
     * @return int
     */
    public function getId(): int
    {
        return (isset($this->data['id'])) ? $this->data['id'] : 0;
    }

    /**
     * Get user's username
     *
     * @return string
     */
    public function getUsername(): string
    {
        return (isset($this->data['username'])) ? $this->data['username'] : '';
    }

    /**
     * Get user's e-mail address
     *
     * @return string
     */
    public function getEmail(): string
    {
        return (isset($this->data['email'])) ? $this->data['email'] : '';
    }

    /**
     * Get user's access level
     *
     * @return int
     */
    public function getAccessLevel(): int
    {
        return (isset($this->data['access_level'])) ? $this->data['access_level'] : 99;
    }

    /**
     * Get user's preference for 2FA
     *
     * @return bool
     */
    public function get2faActive(): bool
    {
        return (isset($this->data['2FA_active'])) ? $this->data['2FA_active'] : false;
    }

    /**
     * Get user's secret key for 2FA
     *
     * @return string
     */
    public function get2faKey(): string
    {
        return (isset($this->data['2FA_key'])) ? $this->data['2FA_key'] : '';
    }

    /**
     * Get user's token for 2FA
     *
     * @return string
     */
    public function get2faToken(): string
    {
        return (isset($this->data['2FA_token'])) ? $this->data['2FA_token'] : '';
    }

    /**
     * Get user's IP-address
     *
     * @return string
     */
    public function getIP(): string
    {
        return $this->fetchIP();
    }

    /**
     * Set any other field from the table
     *
     * @param string $key
     * @param mixed $value
     * @return bool
     */
    public function setData(string $key, $value): bool
    {
        if ($key !== 'password' || $key !== 'salt' || $key !== 'remember_md') {
            $this->data[$key] = $value;
            return true;
        } else {
            return false;
        }
    }

    /**
     * Get any other field from the table
     * Will return 'false' is key 'password', 'salt' or 'remember_me' is accessed
     *
     * @param string $key
     * @return bool|mixed
     */
    public function getData(string $key)
    {
        return ($key !== 'password' || $key !== 'salt' || $key !== 'remember_me') ? $this->data[$key] : false;
    }

    /**
     * Get code for the supplied secret key
     *
     * @param string $secret
     * @return string
     */
    public function get2faCode(string $secret): string
    {
        return $this->googleAuth->getCode($secret);
    }
}
