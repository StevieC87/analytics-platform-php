<?php
// What a form check is allowed to send. ProtectForm hands over the whole
// request, so a sign-up or a checkout route depends entirely on this filter.
//
//   php test/FormsTest.php

require __DIR__ . '/../src/Core.php';
require __DIR__ . '/../src/Forms.php';

use AnalyticsPlatform\Forms;

$failed = 0;
$checked = 0;
function check($name, $ok)
{
    global $failed, $checked;
    $checked++;
    if (!$ok) {
        $failed++;
        fwrite(STDERR, "FAIL: $name\n");
    }
}

$sent = Forms::plainFields(array(
    'name' => 'Ada Lovelace',
    'email' => 'ada@example.com',
    'message' => 'Hello, I would like a quote.',
    'author' => 'Ada',                      // a comment form really sends this
    'subject' => 'Enquiry',
    'phone' => '+44 20 7946 0958',
    'order_number' => '100000123',
    // None of these may leave the server.
    'password' => 'hunter2',
    'pwd' => 'hunter2',
    'passwd' => 'hunter2',
    'user_pass' => 'hunter2',
    'card' => '4111111111111111',
    'cc_number' => '4111111111111111',
    'cvc' => '123',
    'cvv' => '123',
    'expiry' => '12/27',
    'exp_month' => '12',
    'api_key' => 'sk-live-xyz',
    'apikey' => 'sk-live-xyz',
    'auth' => 'Bearer xyz',
    'authorization' => 'Bearer xyz',
    'access_token' => 'xyz',
    'client_secret' => 'xyz',
    'otp' => '123456',
    'mfa_code' => '123456',
    'pin' => '4321',
    'security_code' => '999',
    'ssn' => '078-05-1120',
    'tax_id' => 'GB123',
    'iban' => 'GB33BUKB20201555555555',
    'swift' => 'BUKBGB22',
    'routing' => '021000021',
    'account_number' => '12345678',
    'dob' => '1815-12-10',
    'birthday' => '1815-12-10',
    'licence' => 'ABC123',
    'signature' => 'xyz',
    'private_notes' => 'xyz',
    '_csrf' => 'xyz',
    '_wpnonce' => 'xyz',
    'analytics-shield' => 'answer',
));

foreach (array('name', 'email', 'message', 'author', 'subject') as $keep) {
    check("$keep is still sent, so spam can still be judged", isset($sent[$keep]));
}
$blob = strtolower(json_encode($sent));
check('no password in what is sent', strpos($blob, 'hunter2') === false);
check('no key or token in what is sent', strpos($blob, 'sk-live-xyz') === false && strpos($blob, 'bearer xyz') === false);
check('no card number in what is sent', strpos($blob, '4111111111111111') === false);
check('no shield answer echoed back as a field', !isset($sent['analytics-shield']));
foreach (array('password', 'pwd', 'passwd', 'user_pass', 'card', 'cc_number', 'cvc', 'cvv', 'expiry', 'exp_month',
               'api_key', 'apikey', 'auth', 'authorization', 'access_token', 'client_secret', 'otp', 'mfa_code',
               'pin', 'security_code', 'ssn', 'tax_id', 'iban', 'swift', 'routing', 'account_number', 'dob',
               'birthday', 'licence', 'signature', 'private_notes', '_csrf', '_wpnonce') as $drop) {
    check("$drop is never sent", !isset($sent[$drop]));
}

// A card number typed into a field nobody thought to name "card".
$odd = Forms::plainFields(array('field_12' => 'my card is 4111 1111 1111 1111 thanks'));
check('a card number is taken out of any field', strpos($odd['field_12'], '4111') === false);
check('the rest of the message survives', strpos($odd['field_12'], 'thanks') !== false);

// Numbers that are not cards stay readable, or the spam check loses context.
check('a phone number is kept', strpos($sent['phone'], '7946') !== false);
check('an order number is kept', strpos($sent['order_number'], '100000123') !== false);
check('a long non-Luhn number is kept', Forms::withoutCardNumbers('ref 1234567890123') === 'ref 1234567890123');

$many = array();
for ($i = 0; $i < 200; $i++) {
    $many['f' . $i] = 'x';
}
check('only the first fields are sent', count(Forms::plainFields($many)) <= Forms::MAX_FIELDS);

echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);
