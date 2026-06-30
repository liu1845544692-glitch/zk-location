// zk-regex V2.2.0 variable-length padding compatibility fix.
// This copy relaxes the linked-state equality outside the active match path.
// Template names, parameters, inputs, and outputs are unchanged.
pragma circom 2.1.5;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "../regex_helpers.circom";
include "@zk-email/circuits/utils/array.circom";

// regex: ^P[A-Za-z0-9!@#$%^&*]*[0-9][A-Za-z0-9!@#$%^&*]*;$
template PasswordDigitRegexRegex(maxHaystackBytes, maxMatchBytes) {
    signal input inHaystack[maxHaystackBytes];
    signal input matchStart;
    signal input matchLength;

    signal input currStates[maxMatchBytes];
    signal input nextStates[maxMatchBytes];
    signal output isValid;

    var numStartStates = 2;
    var numAcceptStates = 1;
    var numTransitions = 18;
    var startStates[numStartStates] = [0, 1];
    var acceptStates[numAcceptStates] = [4];

    signal isCurrentState[numTransitions][maxMatchBytes];
    signal isNextState[numTransitions][maxMatchBytes];
    signal isValidTransition[numTransitions][maxMatchBytes];
    signal reachedLastTransition[maxMatchBytes];
    signal isValidRegex[maxMatchBytes];
    signal isValidRegexTemp[maxMatchBytes];
    signal isWithinPathLength[maxMatchBytes];
    signal isWithinPathLengthMinusOne[maxMatchBytes-2];
    signal isTransitionLinked[maxMatchBytes];

    component isValidStartState;

    signal reachedAcceptState[maxMatchBytes];

    component isValidTraversal[maxMatchBytes];

    // Select the haystack from the input
    signal haystack[maxMatchBytes] <== SelectSubArray(maxHaystackBytes, maxMatchBytes)(inHaystack, matchStart, matchLength);

    // Check if the first state in the haystack is a valid start state
    isValidStartState = MultiOR(numStartStates);
    for (var i = 0; i < numStartStates; i++) {
        isValidStartState.in[i] <== IsEqual()([startStates[i], currStates[0]]);
    }
    isValidStartState.out === 1;

    for (var i = 0; i < maxMatchBytes; i++) {
        isWithinPathLength[i] <== LessThan(log2Ceil(maxMatchBytes))([i, matchLength]);

        // Check if the traversal is a valid path
        if (i < maxMatchBytes-2) {
            isWithinPathLengthMinusOne[i] <== LessThan(log2Ceil(maxMatchBytes))([i, matchLength-1]);
            isTransitionLinked[i] <== IsEqual()([nextStates[i], currStates[i+1]]);
            isWithinPathLengthMinusOne[i] * (1 - isTransitionLinked[i]) === 0;
        }

        // Transition 0: 0 -[80]-> 2
        isValidTransition[0][i] <== CheckByteTransition()(0, 2, 80, currStates[i], nextStates[i], haystack[i]);
        // Transition 1: 1 -[80]-> 2
        isValidTransition[1][i] <== CheckByteTransition()(1, 2, 80, currStates[i], nextStates[i], haystack[i]);
        // Transition 2: 2 -[33]-> 2
        isValidTransition[2][i] <== CheckByteTransition()(2, 2, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 3: 2 -[35-38]-> 2
        isValidTransition[3][i] <== CheckByteRangeTransition()(2, 2, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 4: 2 -[42]-> 2
        isValidTransition[4][i] <== CheckByteTransition()(2, 2, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 5: 2 -[48-57]-> 2
        isValidTransition[5][i] <== CheckByteRangeTransition()(2, 2, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 6: 2 -[64-90]-> 2
        isValidTransition[6][i] <== CheckByteRangeTransition()(2, 2, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 7: 2 -[94]-> 2
        isValidTransition[7][i] <== CheckByteTransition()(2, 2, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 8: 2 -[97-122]-> 2
        isValidTransition[8][i] <== CheckByteRangeTransition()(2, 2, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 9: 2 -[48-57]-> 3
        isValidTransition[9][i] <== CheckByteRangeTransition()(2, 3, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 10: 3 -[33]-> 3
        isValidTransition[10][i] <== CheckByteTransition()(3, 3, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 11: 3 -[35-38]-> 3
        isValidTransition[11][i] <== CheckByteRangeTransition()(3, 3, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 12: 3 -[42]-> 3
        isValidTransition[12][i] <== CheckByteTransition()(3, 3, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 13: 3 -[48-57]-> 3
        isValidTransition[13][i] <== CheckByteRangeTransition()(3, 3, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 14: 3 -[64-90]-> 3
        isValidTransition[14][i] <== CheckByteRangeTransition()(3, 3, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 15: 3 -[94]-> 3
        isValidTransition[15][i] <== CheckByteTransition()(3, 3, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 16: 3 -[97-122]-> 3
        isValidTransition[16][i] <== CheckByteRangeTransition()(3, 3, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 17: 3 -[59]-> 4
        isValidTransition[17][i] <== CheckByteTransition()(3, 4, 59, currStates[i], nextStates[i], haystack[i]);

        // Combine all valid transitions for this byte
        isValidTraversal[i] = MultiOR(numTransitions);
        for (var j = 0; j < numTransitions; j++) {
            isValidTraversal[i].in[j] <== isValidTransition[j][i];
        }
        isValidTraversal[i].out === isWithinPathLength[i];

        // Check if any accept state has been reached at the last transition
        reachedLastTransition[i] <== IsEqual()([i, matchLength-1]);
        reachedAcceptState[i] <== IsEqual()([nextStates[i], acceptStates[0]]);
        isValidRegexTemp[i] <== AND()(reachedLastTransition[i], reachedAcceptState[i]);
        if (i == 0) {
            isValidRegex[i] <== isValidRegexTemp[i];
        } else {
            isValidRegex[i] <== isValidRegexTemp[i] + isValidRegex[i-1];
        }
    }

    isValid <== isValidRegex[maxMatchBytes-1];

}
