class external:
    '''
    External instrumentation class
    Monitor a target which doesn't support a debugger, allowing external
    commands to be called
    '''

    def __init__(self, pre=None, post=None, start=None, stop=None):
        '''
        @type  pre:   Function
        @param pre:   Callback called before each test case
        @type  post:  Function
        @param post:  Callback called after each test case for instrumentation. Must return True if the target is still active, False otherwise.
        @type  start: Function
        @param start: Callback called to start the target
        @type  stop:  Function
        @param stop:  Callback called to stop the target
        '''

        self.pre        = pre
        self.post       = post
        self.start      = start
        self.stop       = stop
        self.__dbg_flag = False


    def alive(self):
        '''
        Check if this script is alive. Always True.
        '''

        return True


    def debug(self, msg):
        '''
        Print a debug mesage.
        '''

        if self.__dbg_flag:
            print "EXT-INSTR> %s" % msg


    def pre_send(self, test_number):
        '''
        This routine is called before the fuzzer transmits a test case and ensure the target is alive.

        @type  test_number: Integer
        @param test_number: Test number.
        '''

        if self.pre:
            self.pre()


    def post_send(self):
        '''
        This routine is called after the fuzzer transmits a test case and returns the status of the target.

        @rtype:  Boolean
        @return: Return True if the target is still active, False otherwise.
        '''

        if self.post:
            return self.post()
        else:
            return True


    def start_target(self):
        '''
        Start up the target. Called when post_send failed.
        Returns success of failure of the action
        If no method defined, false is returned
        '''

        if self.start:
            return self.start()
        else:
            return False


    def stop_target(self):
        '''
        Stop the target.
        '''

        if self.stop:
            self.stop()


    def get_crash_synopsis(self):
        '''
        Return the last recorded crash synopsis.

        @rtype:  String
        @return: Synopsis of last recorded crash.
        '''

        return 'External instrumentation detects a crash...\n'
