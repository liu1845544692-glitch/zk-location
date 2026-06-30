pragma circom 2.2.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/utils/regex.circom";
include "./password_policy_generated/lowercase/password_lowercase_regex_regex.circom";
include "./password_policy_generated/uppercase/password_uppercase_regex_regex.circom";
include "./password_policy_generated/digit/password_digit_regex_regex.circom";
include "./password_policy_generated/special/password_special_regex_regex.circom";
include "./password_policy_generated/length/password_length_regex_regex.circom";

template PasswordPolicyCommitmentMain() {
    signal input inHaystack[35];
    signal input matchStart;
    signal input matchLength;

    signal input lowerCurrStates[34];
    signal input lowerNextStates[34];
    signal input upperCurrStates[34];
    signal input upperNextStates[34];
    signal input digitCurrStates[34];
    signal input digitNextStates[34];
    signal input specialCurrStates[34];
    signal input specialNextStates[34];
    signal input lengthCurrStates[34];
    signal input lengthNextStates[34];

    signal input salt;
    signal input passwordCommitment;

    component lowerRegex = PasswordLowercaseRegexRegex(35, 34);
    component upperRegex = PasswordUppercaseRegexRegex(35, 34);
    component digitRegex = PasswordDigitRegexRegex(35, 34);
    component specialRegex = PasswordSpecialRegexRegex(35, 34);
    component lengthRegex = PasswordLengthRegexRegex(35, 34);

    for (var i = 0; i < 35; i++) {
        lowerRegex.inHaystack[i] <== inHaystack[i];
        upperRegex.inHaystack[i] <== inHaystack[i];
        digitRegex.inHaystack[i] <== inHaystack[i];
        specialRegex.inHaystack[i] <== inHaystack[i];
        lengthRegex.inHaystack[i] <== inHaystack[i];
    }

    lowerRegex.matchStart <== matchStart;
    upperRegex.matchStart <== matchStart;
    digitRegex.matchStart <== matchStart;
    specialRegex.matchStart <== matchStart;
    lengthRegex.matchStart <== matchStart;

    lowerRegex.matchLength <== matchLength;
    upperRegex.matchLength <== matchLength;
    digitRegex.matchLength <== matchLength;
    specialRegex.matchLength <== matchLength;
    lengthRegex.matchLength <== matchLength;

    for (var i = 0; i < 34; i++) {
        lowerRegex.currStates[i] <== lowerCurrStates[i];
        lowerRegex.nextStates[i] <== lowerNextStates[i];

        upperRegex.currStates[i] <== upperCurrStates[i];
        upperRegex.nextStates[i] <== upperNextStates[i];

        digitRegex.currStates[i] <== digitCurrStates[i];
        digitRegex.nextStates[i] <== digitNextStates[i];

        specialRegex.currStates[i] <== specialCurrStates[i];
        specialRegex.nextStates[i] <== specialNextStates[i];

        lengthRegex.currStates[i] <== lengthCurrStates[i];
        lengthRegex.nextStates[i] <== lengthNextStates[i];
    }

    lowerRegex.isValid === 1;
    upperRegex.isValid === 1;
    digitRegex.isValid === 1;
    specialRegex.isValid === 1;
    lengthRegex.isValid === 1;

    matchStart === 0;
    inHaystack[0] === 80;

    signal passwordLength;
    passwordLength <== matchLength - 2;

    component minLength = LessThan(6);
    minLength.in[0] <== 7;
    minLength.in[1] <== passwordLength;
    minLength.out === 1;

    component maxLength = LessThan(6);
    maxLength.in[0] <== passwordLength;
    maxLength.in[1] <== 33;
    maxLength.out === 1;

    component haystackBytes[35];
    for (var i = 0; i < 35; i++) {
        haystackBytes[i] = Num2Bits(8);
        haystackBytes[i].in <== inHaystack[i];
    }

    signal passwordPadded[32];
    signal isActive[32];
    component activeLessThan[32];
    for (var i = 0; i < 32; i++) {
        activeLessThan[i] = LessThan(6);
        activeLessThan[i].in[0] <== i;
        activeLessThan[i].in[1] <== passwordLength;
        isActive[i] <== activeLessThan[i].out;
        passwordPadded[i] <== inHaystack[i + 1] * isActive[i];
    }

    signal isTerminator[25];
    signal terminatorSum[26];
    component terminatorEqual[25];
    terminatorSum[0] <== 0;
    for (var j = 9; j <= 33; j++) {
        terminatorEqual[j - 9] = IsEqual();
        terminatorEqual[j - 9].in[0] <== matchLength;
        terminatorEqual[j - 9].in[1] <== j + 1;
        isTerminator[j - 9] <== terminatorEqual[j - 9].out;
        isTerminator[j - 9] * (inHaystack[j] - 59) === 0;
        terminatorSum[j - 8] <== terminatorSum[j - 9] + isTerminator[j - 9];
    }
    terminatorSum[25] === 1;

    signal isBeforeMatch[35];
    component beforeMatchLessThan[35];
    for (var j = 0; j < 35; j++) {
        beforeMatchLessThan[j] = LessThan(6);
        beforeMatchLessThan[j].in[0] <== j;
        beforeMatchLessThan[j].in[1] <== matchLength;
        isBeforeMatch[j] <== beforeMatchLessThan[j].out;
        inHaystack[j] * (1 - isBeforeMatch[j]) === 0;
    }

    signal chunk0Acc[17];
    signal chunk1Acc[17];
    signal chunk0;
    signal chunk1;
    var pow256[16];
    pow256[0] = 1;
    for (var i = 1; i < 16; i++) {
        pow256[i] = pow256[i - 1] * 256;
    }

    chunk0Acc[0] <== 0;
    chunk1Acc[0] <== 0;
    for (var i = 0; i < 16; i++) {
        chunk0Acc[i + 1] <== chunk0Acc[i] + passwordPadded[i] * pow256[i];
        chunk1Acc[i + 1] <== chunk1Acc[i] + passwordPadded[i + 16] * pow256[i];
    }
    chunk0 <== chunk0Acc[16];
    chunk1 <== chunk1Acc[16];

    component passwordHasher = Poseidon(4);
    passwordHasher.inputs[0] <== chunk0;
    passwordHasher.inputs[1] <== chunk1;
    passwordHasher.inputs[2] <== passwordLength;
    passwordHasher.inputs[3] <== salt;

    passwordHasher.out === passwordCommitment;
}

component main {public [passwordCommitment]} = PasswordPolicyCommitmentMain();
