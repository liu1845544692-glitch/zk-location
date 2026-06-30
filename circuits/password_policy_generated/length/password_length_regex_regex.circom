// zk-regex V2.2.0 variable-length padding compatibility fix.
// This copy relaxes the linked-state equality outside the active match path.
// Template names, parameters, inputs, and outputs are unchanged.
pragma circom 2.1.5;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "../regex_helpers.circom";
include "@zk-email/circuits/utils/array.circom";

// regex: ^P[A-Za-z0-9!@#$%^&*]{8,32};$
template PasswordLengthRegexRegex(maxHaystackBytes, maxMatchBytes) {
    signal input inHaystack[maxHaystackBytes];
    signal input matchStart;
    signal input matchLength;

    signal input currStates[maxMatchBytes];
    signal input nextStates[maxMatchBytes];
    signal output isValid;

    var numStartStates = 2;
    var numAcceptStates = 1;
    var numTransitions = 251;
    var startStates[numStartStates] = [0, 1];
    var acceptStates[numAcceptStates] = [35];

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
        // Transition 2: 2 -[33]-> 3
        isValidTransition[2][i] <== CheckByteTransition()(2, 3, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 3: 2 -[35-38]-> 3
        isValidTransition[3][i] <== CheckByteRangeTransition()(2, 3, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 4: 2 -[42]-> 3
        isValidTransition[4][i] <== CheckByteTransition()(2, 3, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 5: 2 -[48-57]-> 3
        isValidTransition[5][i] <== CheckByteRangeTransition()(2, 3, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 6: 2 -[64-90]-> 3
        isValidTransition[6][i] <== CheckByteRangeTransition()(2, 3, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 7: 2 -[94]-> 3
        isValidTransition[7][i] <== CheckByteTransition()(2, 3, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 8: 2 -[97-122]-> 3
        isValidTransition[8][i] <== CheckByteRangeTransition()(2, 3, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 9: 3 -[33]-> 4
        isValidTransition[9][i] <== CheckByteTransition()(3, 4, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 10: 3 -[35-38]-> 4
        isValidTransition[10][i] <== CheckByteRangeTransition()(3, 4, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 11: 3 -[42]-> 4
        isValidTransition[11][i] <== CheckByteTransition()(3, 4, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 12: 3 -[48-57]-> 4
        isValidTransition[12][i] <== CheckByteRangeTransition()(3, 4, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 13: 3 -[64-90]-> 4
        isValidTransition[13][i] <== CheckByteRangeTransition()(3, 4, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 14: 3 -[94]-> 4
        isValidTransition[14][i] <== CheckByteTransition()(3, 4, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 15: 3 -[97-122]-> 4
        isValidTransition[15][i] <== CheckByteRangeTransition()(3, 4, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 16: 4 -[33]-> 5
        isValidTransition[16][i] <== CheckByteTransition()(4, 5, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 17: 4 -[35-38]-> 5
        isValidTransition[17][i] <== CheckByteRangeTransition()(4, 5, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 18: 4 -[42]-> 5
        isValidTransition[18][i] <== CheckByteTransition()(4, 5, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 19: 4 -[48-57]-> 5
        isValidTransition[19][i] <== CheckByteRangeTransition()(4, 5, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 20: 4 -[64-90]-> 5
        isValidTransition[20][i] <== CheckByteRangeTransition()(4, 5, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 21: 4 -[94]-> 5
        isValidTransition[21][i] <== CheckByteTransition()(4, 5, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 22: 4 -[97-122]-> 5
        isValidTransition[22][i] <== CheckByteRangeTransition()(4, 5, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 23: 5 -[33]-> 6
        isValidTransition[23][i] <== CheckByteTransition()(5, 6, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 24: 5 -[35-38]-> 6
        isValidTransition[24][i] <== CheckByteRangeTransition()(5, 6, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 25: 5 -[42]-> 6
        isValidTransition[25][i] <== CheckByteTransition()(5, 6, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 26: 5 -[48-57]-> 6
        isValidTransition[26][i] <== CheckByteRangeTransition()(5, 6, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 27: 5 -[64-90]-> 6
        isValidTransition[27][i] <== CheckByteRangeTransition()(5, 6, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 28: 5 -[94]-> 6
        isValidTransition[28][i] <== CheckByteTransition()(5, 6, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 29: 5 -[97-122]-> 6
        isValidTransition[29][i] <== CheckByteRangeTransition()(5, 6, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 30: 6 -[33]-> 7
        isValidTransition[30][i] <== CheckByteTransition()(6, 7, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 31: 6 -[35-38]-> 7
        isValidTransition[31][i] <== CheckByteRangeTransition()(6, 7, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 32: 6 -[42]-> 7
        isValidTransition[32][i] <== CheckByteTransition()(6, 7, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 33: 6 -[48-57]-> 7
        isValidTransition[33][i] <== CheckByteRangeTransition()(6, 7, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 34: 6 -[64-90]-> 7
        isValidTransition[34][i] <== CheckByteRangeTransition()(6, 7, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 35: 6 -[94]-> 7
        isValidTransition[35][i] <== CheckByteTransition()(6, 7, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 36: 6 -[97-122]-> 7
        isValidTransition[36][i] <== CheckByteRangeTransition()(6, 7, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 37: 7 -[33]-> 8
        isValidTransition[37][i] <== CheckByteTransition()(7, 8, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 38: 7 -[35-38]-> 8
        isValidTransition[38][i] <== CheckByteRangeTransition()(7, 8, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 39: 7 -[42]-> 8
        isValidTransition[39][i] <== CheckByteTransition()(7, 8, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 40: 7 -[48-57]-> 8
        isValidTransition[40][i] <== CheckByteRangeTransition()(7, 8, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 41: 7 -[64-90]-> 8
        isValidTransition[41][i] <== CheckByteRangeTransition()(7, 8, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 42: 7 -[94]-> 8
        isValidTransition[42][i] <== CheckByteTransition()(7, 8, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 43: 7 -[97-122]-> 8
        isValidTransition[43][i] <== CheckByteRangeTransition()(7, 8, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 44: 8 -[33]-> 9
        isValidTransition[44][i] <== CheckByteTransition()(8, 9, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 45: 8 -[35-38]-> 9
        isValidTransition[45][i] <== CheckByteRangeTransition()(8, 9, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 46: 8 -[42]-> 9
        isValidTransition[46][i] <== CheckByteTransition()(8, 9, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 47: 8 -[48-57]-> 9
        isValidTransition[47][i] <== CheckByteRangeTransition()(8, 9, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 48: 8 -[64-90]-> 9
        isValidTransition[48][i] <== CheckByteRangeTransition()(8, 9, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 49: 8 -[94]-> 9
        isValidTransition[49][i] <== CheckByteTransition()(8, 9, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 50: 8 -[97-122]-> 9
        isValidTransition[50][i] <== CheckByteRangeTransition()(8, 9, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 51: 9 -[33]-> 10
        isValidTransition[51][i] <== CheckByteTransition()(9, 10, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 52: 9 -[35-38]-> 10
        isValidTransition[52][i] <== CheckByteRangeTransition()(9, 10, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 53: 9 -[42]-> 10
        isValidTransition[53][i] <== CheckByteTransition()(9, 10, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 54: 9 -[48-57]-> 10
        isValidTransition[54][i] <== CheckByteRangeTransition()(9, 10, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 55: 9 -[64-90]-> 10
        isValidTransition[55][i] <== CheckByteRangeTransition()(9, 10, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 56: 9 -[94]-> 10
        isValidTransition[56][i] <== CheckByteTransition()(9, 10, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 57: 9 -[97-122]-> 10
        isValidTransition[57][i] <== CheckByteRangeTransition()(9, 10, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 58: 10 -[33]-> 11
        isValidTransition[58][i] <== CheckByteTransition()(10, 11, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 59: 10 -[35-38]-> 11
        isValidTransition[59][i] <== CheckByteRangeTransition()(10, 11, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 60: 10 -[42]-> 11
        isValidTransition[60][i] <== CheckByteTransition()(10, 11, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 61: 10 -[48-57]-> 11
        isValidTransition[61][i] <== CheckByteRangeTransition()(10, 11, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 62: 10 -[64-90]-> 11
        isValidTransition[62][i] <== CheckByteRangeTransition()(10, 11, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 63: 10 -[94]-> 11
        isValidTransition[63][i] <== CheckByteTransition()(10, 11, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 64: 10 -[97-122]-> 11
        isValidTransition[64][i] <== CheckByteRangeTransition()(10, 11, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 65: 10 -[59]-> 35
        isValidTransition[65][i] <== CheckByteTransition()(10, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 66: 11 -[33]-> 12
        isValidTransition[66][i] <== CheckByteTransition()(11, 12, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 67: 11 -[35-38]-> 12
        isValidTransition[67][i] <== CheckByteRangeTransition()(11, 12, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 68: 11 -[42]-> 12
        isValidTransition[68][i] <== CheckByteTransition()(11, 12, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 69: 11 -[48-57]-> 12
        isValidTransition[69][i] <== CheckByteRangeTransition()(11, 12, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 70: 11 -[64-90]-> 12
        isValidTransition[70][i] <== CheckByteRangeTransition()(11, 12, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 71: 11 -[94]-> 12
        isValidTransition[71][i] <== CheckByteTransition()(11, 12, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 72: 11 -[97-122]-> 12
        isValidTransition[72][i] <== CheckByteRangeTransition()(11, 12, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 73: 11 -[59]-> 35
        isValidTransition[73][i] <== CheckByteTransition()(11, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 74: 12 -[33]-> 13
        isValidTransition[74][i] <== CheckByteTransition()(12, 13, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 75: 12 -[35-38]-> 13
        isValidTransition[75][i] <== CheckByteRangeTransition()(12, 13, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 76: 12 -[42]-> 13
        isValidTransition[76][i] <== CheckByteTransition()(12, 13, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 77: 12 -[48-57]-> 13
        isValidTransition[77][i] <== CheckByteRangeTransition()(12, 13, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 78: 12 -[64-90]-> 13
        isValidTransition[78][i] <== CheckByteRangeTransition()(12, 13, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 79: 12 -[94]-> 13
        isValidTransition[79][i] <== CheckByteTransition()(12, 13, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 80: 12 -[97-122]-> 13
        isValidTransition[80][i] <== CheckByteRangeTransition()(12, 13, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 81: 12 -[59]-> 35
        isValidTransition[81][i] <== CheckByteTransition()(12, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 82: 13 -[33]-> 14
        isValidTransition[82][i] <== CheckByteTransition()(13, 14, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 83: 13 -[35-38]-> 14
        isValidTransition[83][i] <== CheckByteRangeTransition()(13, 14, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 84: 13 -[42]-> 14
        isValidTransition[84][i] <== CheckByteTransition()(13, 14, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 85: 13 -[48-57]-> 14
        isValidTransition[85][i] <== CheckByteRangeTransition()(13, 14, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 86: 13 -[64-90]-> 14
        isValidTransition[86][i] <== CheckByteRangeTransition()(13, 14, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 87: 13 -[94]-> 14
        isValidTransition[87][i] <== CheckByteTransition()(13, 14, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 88: 13 -[97-122]-> 14
        isValidTransition[88][i] <== CheckByteRangeTransition()(13, 14, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 89: 13 -[59]-> 35
        isValidTransition[89][i] <== CheckByteTransition()(13, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 90: 14 -[33]-> 15
        isValidTransition[90][i] <== CheckByteTransition()(14, 15, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 91: 14 -[35-38]-> 15
        isValidTransition[91][i] <== CheckByteRangeTransition()(14, 15, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 92: 14 -[42]-> 15
        isValidTransition[92][i] <== CheckByteTransition()(14, 15, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 93: 14 -[48-57]-> 15
        isValidTransition[93][i] <== CheckByteRangeTransition()(14, 15, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 94: 14 -[64-90]-> 15
        isValidTransition[94][i] <== CheckByteRangeTransition()(14, 15, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 95: 14 -[94]-> 15
        isValidTransition[95][i] <== CheckByteTransition()(14, 15, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 96: 14 -[97-122]-> 15
        isValidTransition[96][i] <== CheckByteRangeTransition()(14, 15, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 97: 14 -[59]-> 35
        isValidTransition[97][i] <== CheckByteTransition()(14, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 98: 15 -[33]-> 16
        isValidTransition[98][i] <== CheckByteTransition()(15, 16, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 99: 15 -[35-38]-> 16
        isValidTransition[99][i] <== CheckByteRangeTransition()(15, 16, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 100: 15 -[42]-> 16
        isValidTransition[100][i] <== CheckByteTransition()(15, 16, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 101: 15 -[48-57]-> 16
        isValidTransition[101][i] <== CheckByteRangeTransition()(15, 16, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 102: 15 -[64-90]-> 16
        isValidTransition[102][i] <== CheckByteRangeTransition()(15, 16, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 103: 15 -[94]-> 16
        isValidTransition[103][i] <== CheckByteTransition()(15, 16, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 104: 15 -[97-122]-> 16
        isValidTransition[104][i] <== CheckByteRangeTransition()(15, 16, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 105: 15 -[59]-> 35
        isValidTransition[105][i] <== CheckByteTransition()(15, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 106: 16 -[33]-> 17
        isValidTransition[106][i] <== CheckByteTransition()(16, 17, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 107: 16 -[35-38]-> 17
        isValidTransition[107][i] <== CheckByteRangeTransition()(16, 17, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 108: 16 -[42]-> 17
        isValidTransition[108][i] <== CheckByteTransition()(16, 17, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 109: 16 -[48-57]-> 17
        isValidTransition[109][i] <== CheckByteRangeTransition()(16, 17, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 110: 16 -[64-90]-> 17
        isValidTransition[110][i] <== CheckByteRangeTransition()(16, 17, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 111: 16 -[94]-> 17
        isValidTransition[111][i] <== CheckByteTransition()(16, 17, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 112: 16 -[97-122]-> 17
        isValidTransition[112][i] <== CheckByteRangeTransition()(16, 17, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 113: 16 -[59]-> 35
        isValidTransition[113][i] <== CheckByteTransition()(16, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 114: 17 -[33]-> 18
        isValidTransition[114][i] <== CheckByteTransition()(17, 18, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 115: 17 -[35-38]-> 18
        isValidTransition[115][i] <== CheckByteRangeTransition()(17, 18, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 116: 17 -[42]-> 18
        isValidTransition[116][i] <== CheckByteTransition()(17, 18, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 117: 17 -[48-57]-> 18
        isValidTransition[117][i] <== CheckByteRangeTransition()(17, 18, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 118: 17 -[64-90]-> 18
        isValidTransition[118][i] <== CheckByteRangeTransition()(17, 18, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 119: 17 -[94]-> 18
        isValidTransition[119][i] <== CheckByteTransition()(17, 18, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 120: 17 -[97-122]-> 18
        isValidTransition[120][i] <== CheckByteRangeTransition()(17, 18, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 121: 17 -[59]-> 35
        isValidTransition[121][i] <== CheckByteTransition()(17, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 122: 18 -[33]-> 19
        isValidTransition[122][i] <== CheckByteTransition()(18, 19, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 123: 18 -[35-38]-> 19
        isValidTransition[123][i] <== CheckByteRangeTransition()(18, 19, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 124: 18 -[42]-> 19
        isValidTransition[124][i] <== CheckByteTransition()(18, 19, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 125: 18 -[48-57]-> 19
        isValidTransition[125][i] <== CheckByteRangeTransition()(18, 19, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 126: 18 -[64-90]-> 19
        isValidTransition[126][i] <== CheckByteRangeTransition()(18, 19, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 127: 18 -[94]-> 19
        isValidTransition[127][i] <== CheckByteTransition()(18, 19, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 128: 18 -[97-122]-> 19
        isValidTransition[128][i] <== CheckByteRangeTransition()(18, 19, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 129: 18 -[59]-> 35
        isValidTransition[129][i] <== CheckByteTransition()(18, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 130: 19 -[33]-> 20
        isValidTransition[130][i] <== CheckByteTransition()(19, 20, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 131: 19 -[35-38]-> 20
        isValidTransition[131][i] <== CheckByteRangeTransition()(19, 20, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 132: 19 -[42]-> 20
        isValidTransition[132][i] <== CheckByteTransition()(19, 20, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 133: 19 -[48-57]-> 20
        isValidTransition[133][i] <== CheckByteRangeTransition()(19, 20, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 134: 19 -[64-90]-> 20
        isValidTransition[134][i] <== CheckByteRangeTransition()(19, 20, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 135: 19 -[94]-> 20
        isValidTransition[135][i] <== CheckByteTransition()(19, 20, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 136: 19 -[97-122]-> 20
        isValidTransition[136][i] <== CheckByteRangeTransition()(19, 20, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 137: 19 -[59]-> 35
        isValidTransition[137][i] <== CheckByteTransition()(19, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 138: 20 -[33]-> 21
        isValidTransition[138][i] <== CheckByteTransition()(20, 21, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 139: 20 -[35-38]-> 21
        isValidTransition[139][i] <== CheckByteRangeTransition()(20, 21, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 140: 20 -[42]-> 21
        isValidTransition[140][i] <== CheckByteTransition()(20, 21, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 141: 20 -[48-57]-> 21
        isValidTransition[141][i] <== CheckByteRangeTransition()(20, 21, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 142: 20 -[64-90]-> 21
        isValidTransition[142][i] <== CheckByteRangeTransition()(20, 21, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 143: 20 -[94]-> 21
        isValidTransition[143][i] <== CheckByteTransition()(20, 21, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 144: 20 -[97-122]-> 21
        isValidTransition[144][i] <== CheckByteRangeTransition()(20, 21, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 145: 20 -[59]-> 35
        isValidTransition[145][i] <== CheckByteTransition()(20, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 146: 21 -[33]-> 22
        isValidTransition[146][i] <== CheckByteTransition()(21, 22, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 147: 21 -[35-38]-> 22
        isValidTransition[147][i] <== CheckByteRangeTransition()(21, 22, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 148: 21 -[42]-> 22
        isValidTransition[148][i] <== CheckByteTransition()(21, 22, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 149: 21 -[48-57]-> 22
        isValidTransition[149][i] <== CheckByteRangeTransition()(21, 22, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 150: 21 -[64-90]-> 22
        isValidTransition[150][i] <== CheckByteRangeTransition()(21, 22, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 151: 21 -[94]-> 22
        isValidTransition[151][i] <== CheckByteTransition()(21, 22, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 152: 21 -[97-122]-> 22
        isValidTransition[152][i] <== CheckByteRangeTransition()(21, 22, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 153: 21 -[59]-> 35
        isValidTransition[153][i] <== CheckByteTransition()(21, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 154: 22 -[33]-> 23
        isValidTransition[154][i] <== CheckByteTransition()(22, 23, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 155: 22 -[35-38]-> 23
        isValidTransition[155][i] <== CheckByteRangeTransition()(22, 23, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 156: 22 -[42]-> 23
        isValidTransition[156][i] <== CheckByteTransition()(22, 23, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 157: 22 -[48-57]-> 23
        isValidTransition[157][i] <== CheckByteRangeTransition()(22, 23, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 158: 22 -[64-90]-> 23
        isValidTransition[158][i] <== CheckByteRangeTransition()(22, 23, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 159: 22 -[94]-> 23
        isValidTransition[159][i] <== CheckByteTransition()(22, 23, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 160: 22 -[97-122]-> 23
        isValidTransition[160][i] <== CheckByteRangeTransition()(22, 23, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 161: 22 -[59]-> 35
        isValidTransition[161][i] <== CheckByteTransition()(22, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 162: 23 -[33]-> 24
        isValidTransition[162][i] <== CheckByteTransition()(23, 24, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 163: 23 -[35-38]-> 24
        isValidTransition[163][i] <== CheckByteRangeTransition()(23, 24, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 164: 23 -[42]-> 24
        isValidTransition[164][i] <== CheckByteTransition()(23, 24, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 165: 23 -[48-57]-> 24
        isValidTransition[165][i] <== CheckByteRangeTransition()(23, 24, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 166: 23 -[64-90]-> 24
        isValidTransition[166][i] <== CheckByteRangeTransition()(23, 24, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 167: 23 -[94]-> 24
        isValidTransition[167][i] <== CheckByteTransition()(23, 24, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 168: 23 -[97-122]-> 24
        isValidTransition[168][i] <== CheckByteRangeTransition()(23, 24, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 169: 23 -[59]-> 35
        isValidTransition[169][i] <== CheckByteTransition()(23, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 170: 24 -[33]-> 25
        isValidTransition[170][i] <== CheckByteTransition()(24, 25, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 171: 24 -[35-38]-> 25
        isValidTransition[171][i] <== CheckByteRangeTransition()(24, 25, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 172: 24 -[42]-> 25
        isValidTransition[172][i] <== CheckByteTransition()(24, 25, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 173: 24 -[48-57]-> 25
        isValidTransition[173][i] <== CheckByteRangeTransition()(24, 25, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 174: 24 -[64-90]-> 25
        isValidTransition[174][i] <== CheckByteRangeTransition()(24, 25, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 175: 24 -[94]-> 25
        isValidTransition[175][i] <== CheckByteTransition()(24, 25, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 176: 24 -[97-122]-> 25
        isValidTransition[176][i] <== CheckByteRangeTransition()(24, 25, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 177: 24 -[59]-> 35
        isValidTransition[177][i] <== CheckByteTransition()(24, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 178: 25 -[33]-> 26
        isValidTransition[178][i] <== CheckByteTransition()(25, 26, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 179: 25 -[35-38]-> 26
        isValidTransition[179][i] <== CheckByteRangeTransition()(25, 26, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 180: 25 -[42]-> 26
        isValidTransition[180][i] <== CheckByteTransition()(25, 26, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 181: 25 -[48-57]-> 26
        isValidTransition[181][i] <== CheckByteRangeTransition()(25, 26, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 182: 25 -[64-90]-> 26
        isValidTransition[182][i] <== CheckByteRangeTransition()(25, 26, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 183: 25 -[94]-> 26
        isValidTransition[183][i] <== CheckByteTransition()(25, 26, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 184: 25 -[97-122]-> 26
        isValidTransition[184][i] <== CheckByteRangeTransition()(25, 26, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 185: 25 -[59]-> 35
        isValidTransition[185][i] <== CheckByteTransition()(25, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 186: 26 -[33]-> 27
        isValidTransition[186][i] <== CheckByteTransition()(26, 27, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 187: 26 -[35-38]-> 27
        isValidTransition[187][i] <== CheckByteRangeTransition()(26, 27, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 188: 26 -[42]-> 27
        isValidTransition[188][i] <== CheckByteTransition()(26, 27, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 189: 26 -[48-57]-> 27
        isValidTransition[189][i] <== CheckByteRangeTransition()(26, 27, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 190: 26 -[64-90]-> 27
        isValidTransition[190][i] <== CheckByteRangeTransition()(26, 27, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 191: 26 -[94]-> 27
        isValidTransition[191][i] <== CheckByteTransition()(26, 27, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 192: 26 -[97-122]-> 27
        isValidTransition[192][i] <== CheckByteRangeTransition()(26, 27, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 193: 26 -[59]-> 35
        isValidTransition[193][i] <== CheckByteTransition()(26, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 194: 27 -[33]-> 28
        isValidTransition[194][i] <== CheckByteTransition()(27, 28, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 195: 27 -[35-38]-> 28
        isValidTransition[195][i] <== CheckByteRangeTransition()(27, 28, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 196: 27 -[42]-> 28
        isValidTransition[196][i] <== CheckByteTransition()(27, 28, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 197: 27 -[48-57]-> 28
        isValidTransition[197][i] <== CheckByteRangeTransition()(27, 28, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 198: 27 -[64-90]-> 28
        isValidTransition[198][i] <== CheckByteRangeTransition()(27, 28, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 199: 27 -[94]-> 28
        isValidTransition[199][i] <== CheckByteTransition()(27, 28, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 200: 27 -[97-122]-> 28
        isValidTransition[200][i] <== CheckByteRangeTransition()(27, 28, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 201: 27 -[59]-> 35
        isValidTransition[201][i] <== CheckByteTransition()(27, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 202: 28 -[33]-> 29
        isValidTransition[202][i] <== CheckByteTransition()(28, 29, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 203: 28 -[35-38]-> 29
        isValidTransition[203][i] <== CheckByteRangeTransition()(28, 29, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 204: 28 -[42]-> 29
        isValidTransition[204][i] <== CheckByteTransition()(28, 29, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 205: 28 -[48-57]-> 29
        isValidTransition[205][i] <== CheckByteRangeTransition()(28, 29, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 206: 28 -[64-90]-> 29
        isValidTransition[206][i] <== CheckByteRangeTransition()(28, 29, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 207: 28 -[94]-> 29
        isValidTransition[207][i] <== CheckByteTransition()(28, 29, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 208: 28 -[97-122]-> 29
        isValidTransition[208][i] <== CheckByteRangeTransition()(28, 29, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 209: 28 -[59]-> 35
        isValidTransition[209][i] <== CheckByteTransition()(28, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 210: 29 -[33]-> 30
        isValidTransition[210][i] <== CheckByteTransition()(29, 30, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 211: 29 -[35-38]-> 30
        isValidTransition[211][i] <== CheckByteRangeTransition()(29, 30, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 212: 29 -[42]-> 30
        isValidTransition[212][i] <== CheckByteTransition()(29, 30, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 213: 29 -[48-57]-> 30
        isValidTransition[213][i] <== CheckByteRangeTransition()(29, 30, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 214: 29 -[64-90]-> 30
        isValidTransition[214][i] <== CheckByteRangeTransition()(29, 30, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 215: 29 -[94]-> 30
        isValidTransition[215][i] <== CheckByteTransition()(29, 30, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 216: 29 -[97-122]-> 30
        isValidTransition[216][i] <== CheckByteRangeTransition()(29, 30, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 217: 29 -[59]-> 35
        isValidTransition[217][i] <== CheckByteTransition()(29, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 218: 30 -[33]-> 31
        isValidTransition[218][i] <== CheckByteTransition()(30, 31, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 219: 30 -[35-38]-> 31
        isValidTransition[219][i] <== CheckByteRangeTransition()(30, 31, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 220: 30 -[42]-> 31
        isValidTransition[220][i] <== CheckByteTransition()(30, 31, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 221: 30 -[48-57]-> 31
        isValidTransition[221][i] <== CheckByteRangeTransition()(30, 31, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 222: 30 -[64-90]-> 31
        isValidTransition[222][i] <== CheckByteRangeTransition()(30, 31, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 223: 30 -[94]-> 31
        isValidTransition[223][i] <== CheckByteTransition()(30, 31, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 224: 30 -[97-122]-> 31
        isValidTransition[224][i] <== CheckByteRangeTransition()(30, 31, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 225: 30 -[59]-> 35
        isValidTransition[225][i] <== CheckByteTransition()(30, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 226: 31 -[33]-> 32
        isValidTransition[226][i] <== CheckByteTransition()(31, 32, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 227: 31 -[35-38]-> 32
        isValidTransition[227][i] <== CheckByteRangeTransition()(31, 32, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 228: 31 -[42]-> 32
        isValidTransition[228][i] <== CheckByteTransition()(31, 32, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 229: 31 -[48-57]-> 32
        isValidTransition[229][i] <== CheckByteRangeTransition()(31, 32, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 230: 31 -[64-90]-> 32
        isValidTransition[230][i] <== CheckByteRangeTransition()(31, 32, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 231: 31 -[94]-> 32
        isValidTransition[231][i] <== CheckByteTransition()(31, 32, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 232: 31 -[97-122]-> 32
        isValidTransition[232][i] <== CheckByteRangeTransition()(31, 32, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 233: 31 -[59]-> 35
        isValidTransition[233][i] <== CheckByteTransition()(31, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 234: 32 -[33]-> 33
        isValidTransition[234][i] <== CheckByteTransition()(32, 33, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 235: 32 -[35-38]-> 33
        isValidTransition[235][i] <== CheckByteRangeTransition()(32, 33, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 236: 32 -[42]-> 33
        isValidTransition[236][i] <== CheckByteTransition()(32, 33, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 237: 32 -[48-57]-> 33
        isValidTransition[237][i] <== CheckByteRangeTransition()(32, 33, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 238: 32 -[64-90]-> 33
        isValidTransition[238][i] <== CheckByteRangeTransition()(32, 33, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 239: 32 -[94]-> 33
        isValidTransition[239][i] <== CheckByteTransition()(32, 33, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 240: 32 -[97-122]-> 33
        isValidTransition[240][i] <== CheckByteRangeTransition()(32, 33, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 241: 32 -[59]-> 35
        isValidTransition[241][i] <== CheckByteTransition()(32, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 242: 33 -[33]-> 34
        isValidTransition[242][i] <== CheckByteTransition()(33, 34, 33, currStates[i], nextStates[i], haystack[i]);
        // Transition 243: 33 -[35-38]-> 34
        isValidTransition[243][i] <== CheckByteRangeTransition()(33, 34, 35, 38, currStates[i], nextStates[i], haystack[i]);
        // Transition 244: 33 -[42]-> 34
        isValidTransition[244][i] <== CheckByteTransition()(33, 34, 42, currStates[i], nextStates[i], haystack[i]);
        // Transition 245: 33 -[48-57]-> 34
        isValidTransition[245][i] <== CheckByteRangeTransition()(33, 34, 48, 57, currStates[i], nextStates[i], haystack[i]);
        // Transition 246: 33 -[64-90]-> 34
        isValidTransition[246][i] <== CheckByteRangeTransition()(33, 34, 64, 90, currStates[i], nextStates[i], haystack[i]);
        // Transition 247: 33 -[94]-> 34
        isValidTransition[247][i] <== CheckByteTransition()(33, 34, 94, currStates[i], nextStates[i], haystack[i]);
        // Transition 248: 33 -[97-122]-> 34
        isValidTransition[248][i] <== CheckByteRangeTransition()(33, 34, 97, 122, currStates[i], nextStates[i], haystack[i]);
        // Transition 249: 33 -[59]-> 35
        isValidTransition[249][i] <== CheckByteTransition()(33, 35, 59, currStates[i], nextStates[i], haystack[i]);
        // Transition 250: 34 -[59]-> 35
        isValidTransition[250][i] <== CheckByteTransition()(34, 35, 59, currStates[i], nextStates[i], haystack[i]);

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
