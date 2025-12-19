; ###############################################################################
; #     ██╗    ██╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗              #
; #     ██║    ██║██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝              #
; #     ██║ █╗ ██║███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗             #
; #     ██║███╗██║██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║             #
; #     ╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝             #
; #      ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝              #
; #                                                                            #
; #       MOUNT MIDORIYAMA - OBSTACLE 6.5: CONSTRAINT SOLVER TORTURE           #
; #                                                                            #
; ###############################################################################
;
; PURPOSE: Stress test SMT/constraint solvers with pathological instances.
; This is a PIGEONHOLE PROBLEM: 17 pigeons into 16 holes - UNSATISFIABLE!
; Tools must enforce solver timeouts and graceful degradation instead of hangs.
;
; INTENTIONAL SOLVER TORTURE (DO NOT SIMPLIFY):
;
; 1. PIGEONHOLE PRINCIPLE (line 47):
;    - 17 distinct 4-bit values (x0 through x16)
;    - But 4-bit values can only be 0-15 (16 possible values)!
;    - This is MATHEMATICALLY UNSATISFIABLE
;    - Solvers must eventually return UNSAT
;
; 2. NON-LINEAR CONSTRAINTS (lines 49-53):
;    - bvmul (multiplication) is harder than addition
;    - Mixed arithmetic and bitwise operations
;    - Increases solver difficulty significantly
;
; 3. BIT MANIPULATION COMPLEXITY (line 52):
;    - bvshl/bvlshr (shifts), bvxor, bvand, bvor, bvnot
;    - Combinations that stress bit-blasting approaches
;    - Creates complex constraint interdependencies
;
; EXPECTED BEHAVIOR (PASS):
; - Implement timeout mechanism (set-option :timeout 3000)
; - Gracefully return UNSAT or UNKNOWN within time limit
; - NOT hang indefinitely attempting to solve
; - Report that problem is pathological if detected
;
; FAILURE MODE (ELIMINATION):
; - Hanging while attempting exhaustive search
; - Ignoring timeout configuration
; - Crashing on complex constraint combinations
; - Claiming SAT for unsatisfiable instance
;
; ###############################################################################

(set-logic QF_AUFBV)
; TIMEOUT: External harness should still enforce its own timeout; this is advisory.
(set-option :timeout 3000)

; PIGEONHOLE SETUP: 17 pigeons (x0-x16) into 16 holes (4-bit = 0-15 values)
; This is UNSATISFIABLE by the pigeonhole principle!
(declare-fun x0 () (_ BitVec 4))
(declare-fun x1 () (_ BitVec 4))
(declare-fun x2 () (_ BitVec 4))
(declare-fun x3 () (_ BitVec 4))
(declare-fun x4 () (_ BitVec 4))
(declare-fun x5 () (_ BitVec 4))
(declare-fun x6 () (_ BitVec 4))
(declare-fun x7 () (_ BitVec 4))
(declare-fun x8 () (_ BitVec 4))
(declare-fun x9 () (_ BitVec 4))
(declare-fun x10 () (_ BitVec 4))
(declare-fun x11 () (_ BitVec 4))
(declare-fun x12 () (_ BitVec 4))
(declare-fun x13 () (_ BitVec 4))
(declare-fun x14 () (_ BitVec 4))
(declare-fun x15 () (_ BitVec 4))
(declare-fun x16 () (_ BitVec 4))

; UNSATISFIABLE: Cannot have 17 distinct 4-bit values!
(assert (distinct x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15 x16))

; NON-LINEAR CONSTRAINTS: Increase solver difficulty
(assert (= (bvmul x0 x1) (bvadd x2 x3)))           ; Multiplication constraint
(assert (= (bvxor x4 x5) (bvand x6 x7)))           ; Bitwise constraint
(assert (= (bvadd x8 x9) (bvadd x10 x11)))         ; Equality constraint
(assert (= (bvor (bvshl x12 #b0011) (bvlshr x13 #b0001)) (bvxor x14 x15)))  ; Complex bitwise
(assert (= x16 (bvnot (bvxor x0 x8))))             ; Dependency chain

; Expected result: UNSAT (or timeout/unknown for weaker solvers)
(check-sat)
(get-model)
