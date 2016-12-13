<?php

namespace Fishfin;

/**
 * Standalone data sanitization and validation class.
 *
 * @author      fishfin
 * @link        http://aalapshah.in
 * @version     1.0.4
 * @license     MIT
 * 
 * Valigator is a standalone PHP sanitization and validation class that does not
 * require any framework to do its job. It is a very detailed implementation and
 * I hope you will find it useful.
 * 
 * Valigator should work with PHP 5.4.* upwards.
 * 
 * Data sanitization and validation can be run independently of each other, or
 * in succession.
 */
class Valigator
{
    const VERSION = '1.0.4';
    const PLAIN_ERRORMSGS = 0;
    const FIELDS_AND_PLAIN_ERRORMSGS = 1;
    const HTML_ERRORMSGS = 2;
    const FIELDS_AND_HTML_ERRORMSGS = 3;

    // map options passed to functions(parameters) to be called internally
    protected $_aliases = [
        'allow_fraction' => FILTER_FLAG_ALLOW_FRACTION,
        'allow_hex' => FILTER_FLAG_ALLOW_HEX,
        'allow_octal' => FILTER_FLAG_ALLOW_OCTAL,
        'allow_scientific' => FILTER_FLAG_ALLOW_SCIENTIFIC,
        'allow_thousand' => FILTER_FLAG_ALLOW_THOUSAND,
        'alphabet' => 'alphabetic',
        'bool' => 'boolean',
        'encode_amp' => FILTER_FLAG_ENCODE_AMP,
        'encode_high' => FILTER_FLAG_ENCODE_HIGH,
        'encode_low' => FILTER_FLAG_ENCODE_LOW,
        'fileext' => 'fileextension',
        'host_required' => FILTER_FLAG_HOST_REQUIRED,
        'int' => 'integer',
        'ipv4' => FILTER_FLAG_IPV4,
        'ipv6' => FILTER_FLAG_IPV6,
        'path_required' => FILTER_FLAG_PATH_REQUIRED,
        'query_required' => FILTER_FLAG_QUERY_REQUIRED,
        'no_encode_quotes' => FILTER_FLAG_NO_ENCODE_QUOTES,
        'no_priv_range' => FILTER_FLAG_NO_PRIV_RANGE,
        'no_res_range' => FILTER_FLAG_NO_RES_RANGE,
        'null_on_failure' => FILTER_NULL_ON_FAILURE,
        'num' => 'numeric',
        'number' => 'numeric',
        'scheme_required' => FILTER_FLAG_SCHEME_REQUIRED,
        'str' => 'string',
        'strip_high' => FILTER_FLAG_STRIP_HIGH,
        'strip_low' => FILTER_FLAG_STRIP_LOW,
        'strip_backtick' => FILTER_FLAG_STRIP_BACKTICK,        
    ];

    // Filter arguments delimiter default, can be modified using
    // setArgsDelimiter()
    protected $_argsDelimiter = ', ';

    // Customer sanitization methods
    protected $_customSanitizations = array();

    // Custom validation methods
    protected $_customValidations = array();

    // Delimiter for input field hierarchy
    protected $_fieldTreeDelimiter = '.';
    
    // Multibyte supported
    protected $_mbSupported = FALSE;

    // Default validation error messages
    protected $_factoryValidationErrorMsgs = [
        'default' => '{field} is invalid',
        'default_long' => 'Field {field} with value \'{value}\' failed validation {filter}',
        'inexistent_validation' => 'Validation filter {filter} does not exist for {field}, please contact the application owner',
        'alphabetic' => '{field} may only contain alphabetic characters',
        'alphanumeric' => '{field} may only contain alpha-numeric characters',
        'boolean' => '{field} may only contain a true or false value',
        'creditcard' => '{field} does not contain a valid credit card number',
        'date' => '{field} is not a valid date',
        'email' => '{field} is not a valid email address',
        'empty' => '{field} must be empty',
        'endswith' => '{field} does not end with {arg1}',
        'equalsfield' => '{field} does not equal {arg1}',
        'exactlen' => '{field} must be exactly {arg1} characters long',
        'fail' => '{field} failed server validation',
        'fileextension' => '{field} does not have a valid file extension',
        'float' => '{field} may only contain a float value',
        'guidv4' => '{field} is not a valid GUID (v4)',
        'iban' => '{field} is not a valid IBAN',
        'inlist' => '{field} must be one of these values: {args}',
        'integer' => '{field} may only contain an integer value',
        'ip' => '{field} does not contain a valid IP address',
        'ipv4' => '{field} does not contain a valid IPv4 address',
        'ipv6' => '{field} does not contain a valid IPv6 address',
        'jsonstring' => '{field} is not a JSON-encoded string',
        'maxlen'=> '{field} must be {arg1} or shorter in length',
        'maxnumeric' => '{field} must be a numeric value, equal to or lower than {arg1}',
        'minage' => 'The {field} field needs to have an age greater than or equal to {arg1}',
        'minlen'=> '{field} must be {arg1} or longer in length',
        'minnumeric' => 'The {field} field needs to be a numeric value, equal to, or higher than {arg1}',
        'mismatch' => 'There is no validation rule for {field}',
        'notempty' => '{field} cannot be empty',
        'notinlist' => '{field} cannot be one of these values {args}',
        'numeric' => '{field} may only contain numeric characters',
        'pass' => 'Placeholder text, will never be used as {filter} will never fail! :)',
        'personname' => '{field} does not seem to contain a person\'s name',
        'phonenumber' => '{field} does not seem to contain a valid phone number',
        'regex' => '{field} did not match regular expression: {arg1}',
        'required' => '{field} is required',
        'requiredfile' => 'File is required for {field}',
        'startswith' => '{field} does not start with {arg1}',
        'streetaddress' => '{field} does not seem to be a valid street address',
        'url' => 'The {field} field is required to be a valid URL',
        'urlexists' => '{field} URL does not exist',
    ];

    // Error message HTML span attributes
    protected $_emptyErrormsgHTMLSpanAttr = [
        'errormsg' => '',
        'field' => '',
        'value' => '',
        'filter' => '',
        'arg' => '',
    ];

    // Error message HTML span attributes
    protected $_errormsgHTMLSpanAttr = array();

    // Contains fields mapping:
    // 'field1' => [
    //   -- label set to upper-case words by the class by default - , can be
    //   -- overwritten using setFieldLabel method.
    //   'label' => 'Field 1' or 'New Label',
    //   'sanitizations' => [ 'filter' => 'somefilter',
    //                      'args' => ['arg1', 'arg2'],
    //   ]
    //   'validations' => [ 'filter' => 'somefilter',
    //                      'args' => ['arg1', 'arg2'],
    //                      'errormsg' => '{field} with value {value} failed validation.',
    //   ]
    // ]
    protected $_filters = array();

    // Instance attribute containing errors from last run
    //
    // Each error message is of following form:
    // Will contain the following format if validation error encountered
    // 'field1' => [
    //   'value' => 'value of field1 that was validated',
    //   'errormsg' => 'validation error message',
    //   'filter' => 'validation filter name which failed',
    //   'args' => 'args passed to validation filter which failed',
    // ]
    //
    // The error message is picked up in following order:
    //   - Custom error message set for field if internal validation used
    //   - Internal error message if internal validation used
    //   - Custom error message set in addCustomValidation if custom validation used
    //   - Custom error message set for field if custom validation used
    //
    // Following replacements can be done automatically in the error message:
    // {field}   : label of the field validated.
    // {value}   : value the field held when it was validated. If value was not
    //             set, 'empty' (without quotes) will be printed. If value
    //             contained an array, comma-separated string will be printed.
    // {filter}  : filter used for validation.
    // {args}    : comma-delimited args list as string
    // {arg<n>}  : argument passed to filter, where <n> is a valid argument
    //             number.
    //
    protected $_validationErrorLog = array();

    // All HTML Tags that will be removed by sanitize_basichtmltags method
    protected $_basicHTMLTags = '<a><b><blockquote><br><code><dd><dl>'
            . '<em><hr><h1><h2><h3><h4><h5><h6><i><img><label><li><p><span>'
            . '<strong><sub><sup><ul>';

    // All noise words that will be removed by sanitize_noisewords method
    protected $_enNoiseWords = 'about,after,all,also,an,and,another,any,'
            . 'are,as,at,be,because,been,before,being,between,both,but,by,came,'
            . 'can,come,could,did,do,each,for,from,get, got,has,had,he,have,'
            . 'her,here,him,himself,his,how,if,in,into,is,it,its,it\'s,like,'
            . 'make,many,me,might,more,most,much,must,my,never,now,of,on,only,'
            . 'or,other,our,out,over,said,same,see,should,since,some,still,'
            . 'such,take,than,that,the,their,them,then,there,these,they,this,'
            . 'those,through,to,too,under,up,very,was,way,we,well,were,what,'
            . 'where,which,while,who,with,would,you,your,a,b,c,d,e,f,g,h,i,j,k,'
            . 'l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,$,1,2,3,4,5,6,7,8,9,0,_';

    /**
     * Magic method to generate the validation error messages.
     * 
     * @param array Input data of the form {'field1' => 'value1', 'field2' =>
     * 'value2'}
     *
     * @return array
     */
    private function _setFieldLabelAndHierarchy($field)
    {
        if (!isset($this->_filters[$field]['field'])
                || !isset($this->_filters[$field]['parents'])) {
            $hierarchy = explode($this->_fieldTreeDelimiter, $field);
            $hierarchyMaxDepth = count($hierarchy) - 1;
            $parentHierarchy = array();

            $this->_filters[$field]['parents'] = array();
            foreach ($hierarchy as $depth => $node) {
                if ($depth == $hierarchyMaxDepth) {
                    $this->_filters[$field]['field'] = $node;
                } else {
                    $this->_filters[$field]['parents'][] = $node;
                }
            }
        }

        if (!isset($this->_filters[$field]['label'])) {
            $this->_filters[$field]['label'] =
                    $this->_convertVariableNameToUpperCaseWords($this->_filters[$field]['field']);
        }
    }

    /**
     * Magic method to generate the validation error messages.
     * 
     * @param array Input data of the form {'field1' => 'value1', 'field2' =>
     * 'value2'}
     *
     * @return object
     */
    public function __construct(array $filters = array(), string $fieldHierarchyDelimiter = '.')
    {
        $this->_mbSupported = function_exists('mb_detect_encoding');
        
        $this->_errormsgHTMLSpanAttr = $this->_emptyErrormsgHTMLSpanAttr;

        $this->setFieldHierarchyDelimiter($fieldHierarchyDelimiter);

        foreach ($filters as $field => $fieldFilter) {

            if (isset($fieldFilter['label'])) {
                $this->_filters[$field]['label'] = $fieldFilter['label'];          
            }

            $this->_setFieldLabelAndHierarchy($field);

            $this->setSanitizations(
                    isset($fieldFilter['sanitizations'])
                    ? array($field => $fieldFilter['sanitizations'])
                    : (isset($fieldFilter['sanitization'])
                        ? array($field => $fieldFilter['sanitization'])
                        : array()));

            $this->setValidations(
                    isset($fieldFilter['validations'])
                    ? array($field => $fieldFilter['validations'])
                    : (isset($fieldFilter['validation'])
                        ? array($field => $fieldFilter['validation'])
                        : array()));
        }

        return $this;
    }

    /**
     * Magic method to generate the validation error messages.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->getValidationErrors();
    }

    /**
     * Ensure that the field counts match the validation rule counts.
     *
     * @param array $data
     */
    private function _checkFields(array $data)
    {
        $ruleset = $this->_filters['validations'];
        $mismatch = array_diff_key($data, $ruleset);
        $fields = array_keys($mismatch);

        foreach ($fields as $field) {
            $this->_validationErrorLog[] = array(
                'field' => $field,
                'value' => $data[$field],
                'filter' => 'mismatch',
                'args' => array(),
            );
        }
    }

    /**
     * Converts input validation rules array to string. Some examples of
     * conversion are:
     *
     * {'filter' => 'filterName', 'args' => {'arg1', 'arg2'}, 'errormsg' =>
     * 'Error Text'} to "filterName:arg1,arg2;'Error Text'"
     *
     * @param array $fieldFilterArray
     *
     * @return string
     */
    private function _convertFieldFiltersArrayToString(array $fieldFilterArray)
    {
        $fieldFilterString = '';

        if (is_array($fieldFilterArray)) {
            $fieldValidationsFlattened = array();
            foreach ($fieldFilterArray as $fieldValidation) {
                if (isset($fieldValidation['filter'])) {
                    $fieldValidationsFlattened[] =
                            $fieldValidation['filter'] . ':'
                            . (isset($fieldValidation['args'])
                                    ? implode(',', $fieldValidation['args'])
                                    : '') . ';\''
                            . (isset($fieldValidation['errormsg'])
                                    ? $fieldValidation['errormsg']
                                    : '') . '\'';                    
                }
            }
            $fieldFilterString = implode('|', $fieldValidationsFlattened);
        }

        return $fieldFilterString;
    }

    /**
     * Converts input validation rules string to array. Some examples of
     * conversion are:
     *
     * "filterName:arg1,arg2;'Error Text'" to {'filter' => 'filterName',
     * 'args' => {'arg1', 'arg2'}, 'errormsg' => 'Error Text'}
     *
     * "filterName:arg1" to {'filter' => 'filterName',
     * 'args' => {'arg1'}, 'errormsg' => ''}
     *
     * "filterName:;'Error Text'" to {'filter' => 'filterName',
     * 'args' => {}, 'errormsg' => 'Error Text'}
     *
     * @param string $fieldFilterString
     *
     * @return array
     *
     * @throws Exception if preg_match_all fails
     */
    private function _convertFieldFiltersStringToArray(string $fieldFilterString
            , bool $isValidation = TRUE)
    {
        $fieldFilterArray = array();
        $filters = array();

        if (!preg_match_all('/'                     // group0: filter group
                                                    //     begin parsing filter name
                . '[\|\s\'"]*'                      //                            no-capture: pipe, none or more spaces, single or double quotes
                . '(?P<filter>[^:;].+?)'            // group1: filter name        capture   : at least one char (any char), cannot start with : or ; (as they are used later in parsing), lazy (stop at first match)
                . '(?:[\s\'"]*)'                    //                            no-capture: none or more spaces, single or double quotes
                                                    //     end parsing filter name
                . '(?:$|\|'                         //                            no-capture: end-of-string or pipe (filter name with no args or message)
                .   '|'                             //                            or
                                                    //     begin parsing arguments list
                .   '(?::'                          //                            no-capture: colon (start of args)
                .     '(?P<args>.*?)'               // group2: arguments          capture   : none or more characters, lazy (stop at first match)
                                                    //     end parsing arguments list
                .     '(?:'                         //                            no-capture: followed by...
                .       '(?:$|\|)'                  //                            no-capture: end-of-string or pipe (i.e. filter name with no message)
                .       '|'                         //                            or
                .       '(?:;'                      //                            no-capture: semi-colon (end of args)
                                                    //     begin parsing custom error message
                .         '(?:'                     //                            no-capture: followed by
                .           '[\s]*'                 //                            no-capture: leading spaces
                .           '(?P<quote>[\'"]?)'     // group3: begin-quote        capture   : none or more spaces, single or double quotes
                .           '(?P<errormsg>.*?)'     // group4: custom error msg   capture   : none or more characters, lazy (stop at first match)
                .           '\g{quote}'             //                            no-capture: same as start quote
                .           '[\s]*'                 //                            no-capture: trailing spaces
                .           '(?:$|\|)'              // no-capture: end-of-string or pipe
                .         ')'
                                                    //     end parsing custom error message
                .       ')'
                .     ')'
                .   ')'
                . ')'
                . '/i',
                $fieldFilterString, $filters, PREG_SET_ORDER)) {
            throw new \Exception('Invalid filter encountered: ' . $fieldFilterString);
        }

        foreach ($filters as $filter) {
            if (isset($filter['filter'])
                    && ($this->_mbSupported
                            ? (mb_strcut($filter['filter'], 0, 1) != '/')
                            : (substr($filter['filter'], 0, 1) != '/'))) {
                $fieldFilter = [
                    'filter' => strtolower($filter['filter']),
                    'args' => (isset($filter['args']) ? array_map('trim', explode(",", $filter['args'])) : array()),
                ];
                if ($isValidation) {
                    $fieldFilter['errormsg'] = isset($filter['errormsg']) ? $filter['errormsg'] : '';
                }
                $fieldFilterArray[] = $fieldFilter;
            }
        }

        return $fieldFilterArray;
    }

    /**
     * Converts snake_case, camelCase, PascalCase, lisp-case, Train-Case to
     * Human Readable Upper Case Words string.
     *
     * @param string $developerReadable
     *
     * @return string String
     */
    private function _convertVariableNameToUpperCaseWords(string $developerReadable)
    {
        return rtrim(ucwords(
            preg_replace('/[\s_-]*'            // space, _ or - ignore
                . '('                          // group 1 start
                . '(?:[A-Z]?[a-z]+)'           // ?: ignore group, 0-1 capital letters, 1+ small letters
                . '|'                          // or
                . '(?:[A-Z]+(?=[A-Z][^A-Z]))'  // ?: ignore group, 1+ capital letters, lookahead 1st capital letter followed by at least one small letter
                . '|'                          // or
                . '(?:[A-Z])'                  // ?: ignore group, 1 capital letter
                . '|'                          // or
                . '(?:[^A-Za-z-]+)'            // ?: ignore group, 1+ any letters
                . ')'                          // group 1 end
                . '[\s_-]*/',                  // space, _ or - ignore
                '\1 ',                         // replace with self followed by blank
                $developerReadable))
        );
    }

    /**
     * Gets synonym from local array.
     *
     * @param string $lookFor
     *
     * @return mixed String or number, based on True(boolean) or the array of error messages
     */
    private function _findAlias(string $lookFor)
    {
        return array_key_exists($lookForLowerCase = strtolower($lookFor), $this->_aliases)
                ? $this->_aliases[$lookForLowerCase] : $lookFor;            
    }

    /**
     * Gets field value from input
     * 
     * @param string $field
     * @param mixed $input
     *
     * @return string
     */

    private function &_getFieldValueFromInput($field, &$input, $autoAddParentage = FALSE) {
        $fieldValue = NULL;
        $parentageExists = TRUE;
        $rollingInput = &$input;

        foreach ($this->_filters[$field]['parents'] as $parentDepth => $parent) {
            if (is_array($rollingInput)
                    && ((array_key_exists($parent, $rollingInput)
                        || $autoAddParentage))) {
                if (array_key_exists($parent, $rollingInput)) {
                    $rollingInput = &$rollingInput[$parent];
                } else {
                    $rollingInput = &$rollingInput[$parent];
                    $rollingInput = array();
                }
            } else {
                $parentageExists = FALSE;
                break;
            }
        }

        if ($parentageExists && is_array($rollingInput)) {
            if (array_key_exists($this->_filters[$field]['field'], $rollingInput)) {
                if (!is_array($rollingInput[$this->_filters[$field]['field']])) {
                    $fieldValue = &$rollingInput[$this->_filters[$field]['field']];
                }
            } else if ($autoAddParentage) {
                $fieldValue = &$rollingInput[$this->_filters[$field]['field']];
                $fieldValue = '';
            }
        }

        return $fieldValue;
    }

    /**
     * Retrieves standard validation error messages from internal array
     *
     * @param string  $key
     * 
     * @return string Error msg
     */
    private function _getValidationErrorMsg(string $key)
    {
        if (array_key_exists($key, $this->_factoryValidationErrorMsgs)) {
            $errorMsg = $this->_factoryValidationErrorMsgs[$key];
        } elseif (array_key_exists($key = $this->_findAlias($key)
                , $this->_factoryValidationErrorMsgs)) {
            $errorMsg = $this->_factoryValidationErrorMsgs[$key];
        } else {
            $errorMsg = $this->_factoryValidationErrorMsgs['default_long'];            
        }
        
        return $errorMsg;
    }

    /**
     * Replaces tags in error messages with values.
     *
     * @param string $errorMsg
     * @param string $field
     * @param mixed  $input (which has field => value) or value
     * @param string $filter
     * @param array  $args
     * @param string $fieldSpan (inject span around {field})
     * @param string $valueSpan (inject span around {value})
     * @param string $filterSpan (inject span around {filter})
     * @param string $argSpan (inject span around {args}, {arg1} etc.)
     *
     * @return string Converted error message
     */
    private function _readableErrorMsg(string $errorMsg, string $field
            , $value = '', string $filter = '', array $args = array()
            , string $errormsgSpan = '', string $fieldSpan = ''
            , string $valueSpan = '', string $filterSpan = ''
            , string $argSpan = '')
    {
        $spanTags = array();
        foreach (['errormsg', 'field', 'value', 'filter', 'arg'] as $element) {
            $spanVar = "{$element}Span";
            $spanTags[$element] = ($$spanVar == '')
                    ? ['', '']
                    : ["<span {$$spanVar}>", "</span>"];
        }

        $errorMsg = str_replace('{field}'
                , $spanTags['field'][0] . $this->_filters[$field]['label']
                        . $spanTags['field'][1]
                , $errorMsg);

        if ($value == '') {
            $value = 'empty';
        }
        $errorMsg = str_replace('{value}'
                , $spanTags['value'][0] . $value . $spanTags['value'][1]
                , $errorMsg);

        $errorMsg = str_replace('{filter}'
                , $spanTags['filter'][0] . $filter . $spanTags['filter'][1]
                , $errorMsg);

        $errorMsg = str_replace('{args}'
                , $spanTags['arg'][0]
                    . implode($spanTags['arg'][1]
                            . $this->_argsDelimiter . $spanTags['arg'][0], $args)
                    . $spanTags['arg'][1]
                , $errorMsg);

        foreach ($args as $index => $arg) {
            $argIndex = $index + 1;
            $errorMsg = str_replace("{arg{$argIndex}}"
                    , $spanTags['arg'][0] . $arg . $spanTags['arg'][1]
                    , $errorMsg);
        }

        return $spanTags['errormsg'][0] . $errorMsg . $spanTags['errormsg'][1];      
    }

    /**
     * Adds a custom sanitization using a callback function.
     *
     * @param string   $sanitization
     * @param callable $callback
     *
     * @return null
     *
     * @throws Exception
     */
    public function addCustomSanitization(string $filter, callable $callback)
    {
        $filter = strtolower($filter);
        $method = "sanitize_{$filter}";

        if (method_exists(__CLASS__, $method) || isset($this->_customSanitizations[$filter])) {
            throw new \Exception("Sanitization filter {$filter} already exists");
        }

        $this->_customSanitizations[$filter] = $callback;

        return $this;
    }

    /**
     * Adds a custom validation rule using a callback function.
     *
     * @param string   $validation
     * @param callable $callback
     *
     * @return null
     *
     * @throws Exception
     */
    public function addCustomValidation(string $filter, callable $callback
            , string $defaultErrorMsg = NULL)
    {
        $filter = strtolower($filter);
        $method = "validate_{$filter}";

        if (method_exists(__CLASS__, $method) || isset($this->_customValidations[$filter])) {
            throw new \Exception("Validation filter {$filter} already exists.");
        }

        $this->_customValidations[$filter]['callback'] = $callback;

        if ($defaultErrorMsg === NULL) {
            $defaultErrorMsg = $this->_factoryValidationErrorMsgs['default_long'];
        }
        $this->_customValidations[$filter]['errormsg'] = $defaultErrorMsg;

        return $this;
    }

    /**
     * Sanitize the input data.
     *
     * @param array $input
     * @param null  $fields
     * @param bool  $utf8_encode
     *
     * @return array
     */
    public function cleanse(array $input, array $fields = array(), $utf8_encode = true)
    {
        $magic_quotes = (bool) get_magic_quotes_gpc();

        if (empty($fields)) {
            $fields = array_keys($input);
        }

        $return = array();

        foreach ($fields as $field) {
            if (!isset($input[$field])) {
                continue;
            } else {
                $value = $input[$field];
                if (is_array($value)) {
                    $value = $this->cleanse($value);
                }
                if (is_string($value)) {
                    if ($magic_quotes === TRUE) {
                        $value = stripslashes($value);
                    }

                    if (strpos($value, "\r") !== FALSE) {
                        $value = trim($value);
                    }

                    if (function_exists('iconv') && function_exists('mb_detect_encoding') && $utf8_encode) {
                        $current_encoding = mb_detect_encoding($value);

                        if ($current_encoding != 'UTF-8' && $current_encoding != 'UTF-16') {
                            $value = iconv($current_encoding, 'UTF-8', $value);
                        }
                    }

                    $value = filter_var($value, FILTER_SANITIZE_STRING);
                }

                $return[$field] = $value;
            }
        }

        return $return;
    }

    /**
     * Clears sanitizations for input fields. If no input is sent, sanitizations
     * of all fields are cleared.
     *
     * @param mixed $clearSanitizationsForFields
     *
     * @return object
     */
    public function clearSanitizations($clearSanitizationsForFields = NULL)
    {
        if ($clearSanitizationsForFields === NULL) {
            $clearSanitizationsForFields = array_keys($this->_filters);
        } else {
            $clearSanitizationsForFields = (array) $clearValidationsForFields;
        }

        foreach ($clearSanitizationsForFields as $field) {
            if (isset($this->_filters[$field])) {
                $this->_filters[$field]['sanitizations'] = array();
                //unset($this->_filters[$field]['sanitizations']);
            }
        }
        
        return $this;
    }

    /**
     * Clears validations for input fields. If no input is sent, validations of
     * all fields are cleared.
     *
     * @param mixed $clearValidationsForFields
     *
     * @return object
     */
    public function clearValidations($clearValidationsForFields = NULL)
    {
        if ($clearValidationsForFields === NULL) {
            $clearValidationsForFields = array_keys($this->_filters);
        } else {
            $clearValidationsForFields = (array) $clearValidationsForFields;
        }

        foreach ($clearValidationsForFields as $field) {
            if (isset($this->_filters[$field])) {
                $this->_filters[$field]['validations'] = array();
                //unset($this->_filters[$field]['validations']);
            }
        }
        
        return $this;
    }

    /**
     * Return the error array from the last validation run.
     *
     * @return array
     */
    public function getValidationErrors(
            int $returnFormat = self::PLAIN_ERRORMSGS
            , string $errorDelimiter = NULL)
    {
        $formatAsHTML = ($returnFormat === self::HTML_ERRORMSGS
                || $returnFormat === self::FIELDS_AND_HTML_ERRORMSGS);
        $includeFields =  ($returnFormat === self::FIELDS_AND_PLAIN_ERRORMSGS
                || $returnFormat === self::FIELDS_AND_HTML_ERRORMSGS);

        $formattedErrormsgs = array();

        $spans = $formatAsHTML
                ? $this->_errormsgHTMLSpanAttr
                : $this->_emptyErrormsgHTMLSpanAttr;

        foreach ($this->_validationErrorLog as $validationErrorAt) {
            $formattedErrormsg =  $this->_readableErrorMsg(
                        $validationErrorAt['errormsg']
                        , $validationErrorAt['field']
                        , $validationErrorAt['value']
                        , $validationErrorAt['filter']
                        , $validationErrorAt['args']
                        , $spans['errormsg']
                        , $spans['field']
                        , $spans['value']
                        , $spans['filter']
                        , $spans['arg']);

            $formattedErrormsgs[] = $includeFields
                    ? [$validationErrorAt['field'] => $formattedErrormsg]
                    : $formattedErrormsg;
        }
        
        if ($errorDelimiter !== NULL) {
            $formattedErrormsgs = implode($errorDelimiter, $formattedErrormsgs);
        }
        return $formattedErrormsgs;
    }

    /**
     * Perform XSS clean to prevent cross site scripting.
     *
     * @static
     *
     * @param array $data
     *
     * @return array
     */
    public function xss_clean(array $data)
    {
        foreach ($data as $k => $v) {
            $data[$k] = filter_var($v, FILTER_SANITIZE_STRING);
        }

        return $data;
    }

    /**
     * Helper method to extract an element from an array safely
     *
     * @param mixed $key
     * @param array $array
     * @param mixed $default
     * 
     * @return mixed
     */
    public function field($key, array $array, $default = NULL)
    {
      if(!is_array($array)) {
        return NULL;
      }

      if(isset($array[$key])) {
        return $array[$key];
      } else {
        return $default;
      }
    }

    /**
     * Sets span attributes to be used in HTML validation error messages.
     *
     * @param string   $errormsgSpan
     * @param string   $fieldSpan
     * @param string   $valueSpan
     * @param string   $filterSpan
     * @param string   $argSpan
     *
     * @return object
     */
    public function setHTMLSpansForErrorMsgs(string $errormsgSpan = NULL
            , string $fieldSpan = NULL, string $valueSpan = NULL
            , string $filterSpan = NULL, string $argSpan = NULL)
    {
        foreach (['errormsg', 'field', 'value', 'filter', 'arg'] as $element) {
            $elementSpanVar = "{$element}Span";
            $this->_errormsgHTMLSpanAttr[$element] =
                    ($$elementSpanVar === NULL || !is_string($$elementSpanVar))
                    ? '' : $$elementSpanVar;
        }
        
        return $this;  // returning object to facilitate chaining
    }

    /**
     * Updates the filter arguments delimiter.
     *
     * @param string   $argsDelimiter
     *
     * @return object
     */
    public function setArgsDelimiter(string $argsDelimiter)
    {
        $this->_argsDelimiter = $argsDelimiter;
        
        return $this;  // returning object to facilitate chaining
    }

    /**
     * Updates the field tree delimiter.
     *
     * @param string   $fieldHierarchyDelimiter
     *
     * @return object
     */
    public function setFieldHierarchyDelimiter(string $fieldHierarchyDelimiter)
    {
        $this->_fieldTreeDelimiter = $fieldHierarchyDelimiter;

        return $this;
    }

    /**
     * Set/overwrite field labels.
     *
     * @param array $fieldLabels
     *
     * @return object
     */
    public function setLabels(array $fieldLabels)
    {
        foreach ($fieldLabels as $field => $label) {
            $this->_filters[$field]['label'] = $label;
        }
        
        return $this;
    }

    /**
     * Adds sanitizations for input fields.
     *
     * @param array $fieldSanitizations
     *
     * @return object
     */
    public function setSanitizations(array $fieldSanitizations
            , bool $mergeBefore = FALSE)
    {
        foreach($fieldSanitizations as $field => $fieldFiltersString) {

            $this->_setFieldLabelAndHierarchy($field);

            if (!isset($this->_filters[$field]['sanitizations'])) {
                $this->_filters[$field]['sanitizations'] = array();
            }

            $fieldFiltersArray =
                    $this->_convertFieldFiltersStringToArray($fieldFiltersString, FALSE);

            $this->_filters[$field]['sanitizations'] = ($mergeBefore === TRUE)
                    ? array_merge_recursive($fieldFiltersArray,
                            $this->_filters[$field]['sanitizations'])
                    : array_merge_recursive($this->_filters[$field]['sanitizations']
                            , $fieldFiltersArray);
        }
        
        return $this;
    }

    /**
     * Adds validations for input fields.
     *
     * @param array $fieldValidations
     *
     * @return object
     */
    public function setValidations(array $fieldValidations)
    {
        foreach($fieldValidations as $field => $fieldFiltersString) {

            $this->_setFieldLabelAndHierarchy($field);

            if (!isset($this->_filters[$field]['validations'])) {
                $this->_filters[$field]['validations'] = array();
            }

            $fieldFiltersArray =
                    $this->_convertFieldFiltersStringToArray($fieldFiltersString);

            $this->_filters[$field]['validations'] =
                    array_merge_recursive($this->_filters[$field]['validations']
                            , $fieldFiltersArray);
        }
        
        return $this;
    }

    /**
     * Run sanitizations filtering and validation after each other.
     *
     * @param mixed $input can be only array or null
     * @param bool  $checkFields
     *
     * @return array
     *
     * @throws Exception
     */
    public function run($input, $checkFields = false)
    {
        $sanitizedInput = $this->runSanitizations($input);

        $validated = $this->runValidations($sanitizedInput);

        //if ($checkFields === TRUE) {
        //    $this->_checkFields($sanitizedInput);
        //}

        return ($validated === FALSE) ? FALSE : $sanitizedInput;
    }

    /**
     * Sanitize the input data according to the specified sanitizations set.
     *
     * @param mixed $input can be only array or null
     *
     * @throws Exception
     *
     * @return mixed
     *
     * @throws Exception
     */
    public function runSanitizations($input)
    {
        if ($input === NULL) {
            $input = array();
        }

        $this->_validationErrorLog = array();  // initialize error log

        foreach ($this->_filters as $field => $fieldFilters) {
            if (!isset($fieldFilters['sanitizations'])) {
                continue;
            }

            $fieldValue = &$this->_getFieldValueFromInput($field, $input, FALSE);

            $filterSkipCount = 0;

            foreach ($fieldFilters['sanitizations'] as $fieldFilter) {
                if ($filterSkipCount > 0) {
                    $filterSkipCount--;
                    continue;
                }

                $filter = $fieldFilter['filter'];
                $filterSynonym = $this->_findAlias($filter);

                if (count($fieldFilter['args']) > 0) {
                    $args = $fieldFilter['args'];
                    foreach($args as $i => $arg) {
                        $argsSynonyms[$i] = $this->_findAlias($arg);
                    }                    
                } else {
                    $argsSynonyms = $args = NULL;
                }

                if ($filterSynonym === 'skip') {
                    if ($argsSynonyms === NULL
                            || count($argsSynonyms) === 0
                            || $argsSynonyms[0] === 'all') {
                        break;         // break out of foreach
                    } else {
                        $filterSkipCount = (!ctype_digit($argsSynonyms[0])
                                || (int) $argsSynonyms[0] < 1)
                                ? 0 : (int) $argsSynonyms[0];
                        continue;
                    }
                }

                if ($filterSynonym == 'default') {
                    $method = "sanitize_{$filterSynonym}";
                    $fieldValue = &$this->_getFieldValueFromInput($field, $input, TRUE);
                    $fieldValue = $this->$method($fieldValue, $argsSynonyms);
                } else if ($fieldValue !== NULL) {
                    switch (TRUE) {
                        case (isset($this->_customSanitizations[$filter])):
                            $fieldValue = call_user_func($this->_customSanitizations[$filter]
                                    , $fieldValue, $argsSynonyms);
                            break;
                        case (is_callable(array($this, $method = "sanitize_{$filter}"))
                              || is_callable(array($this, $method = "sanitize_{$filterSynonym}"))):
                            $fieldValue = $this->$method($fieldValue, $argsSynonyms);
                            break;
                        case (function_exists($phpFilter = $filter)
                              || function_exists($phpFilter = $filterSynonym)):
                            $fieldValue = $phpFilter($fieldValue);
                            break;
                        default:
                            throw new \Exception("Sanitization filter {$filter} does not exist.");
                    }
                }
            }
        }

        return $input;
    }

    /**
     * Perform data validation against the provided ruleset.
     *
     * @param mixed $input can be only array or null
     *
     * @return mixed
     */
    public function runValidations($input)
    {
        if ($input === NULL) {
            $input = array();
        }

        $this->_validationErrorLog = array();  // initialize error log

        foreach ($this->_filters as $field => $fieldFilters) {
            if (!isset($fieldFilters['validations'])) {
                continue;
            }

            $fieldValue = &$this->_getFieldValueFromInput($field, $input, FALSE);

            $filterSkipCount = 0;

            foreach ($fieldFilters['validations'] as $fieldFilter) {
                if ($filterSkipCount > 0) {
                    $filterSkipCount--;
                    continue;
                }

                $filter = $fieldFilter['filter'];
                $filterSynonym = $this->_findAlias($filter);


                $args = $fieldFilter['args'];
                if (count($fieldFilter['args']) > 0) {
                    foreach($args as $i => $arg) {
                        $argsSynonyms[$i] = $this->_findAlias($arg);
                    }                    
                } else {
                    $argsSynonyms = $args;
                }

                if ($filterSynonym === 'skip') {
                    if ($argsSynonyms === NULL
                            || count($argsSynonyms) === 0
                            || $argsSynonyms[0] === 'all') {
                        break;         // break out of foreach
                    } else {
                        $filterSkipCount = (!ctype_digit($argsSynonyms[0])
                                || (int) $argsSynonyms[0] < 1)
                                ? 0 : (int) $argsSynonyms[0];
                        continue;
                    }
                }

                $validationErrorMsg = array();

                if (in_array($method = $filter, ['required', 'notempty'])
                    || in_array($method = $filterSynonym, ['required', 'notempty'])) {
                    $method = "validate_{$method}";
                    $validationPassed = $this->$method($fieldValue, $argsSynonyms);
                    if (!$validationPassed) {
                        $validationErrorMsg[] = $fieldFilter['errormsg'];
                        $validationErrorMsg[] =
                                $this->_getValidationErrorMsg($filter);
                    }
                } else if ($fieldValue === NULL) {
                    $validationPassed = TRUE;
                } else {
                    switch (TRUE) {
                        case (isset($this->_customValidations[$filter]['callback'])):
                            $validationPassed = call_user_func(
                                    $this->_customValidations[$filter]['callback']
                                    , $fieldValue, $argsSynonyms);
                            if (!$validationPassed) {
                                $validationErrorMsg[] = $fieldFilter['errormsg'];
                                $validationErrorMsg[] = $this->_customValidations[$filter]['errormsg'];
                                $validationErrorMsg[] = $this->_factoryValidationErrorMsgs['default_long'];
                            }
                            break;
                        case (is_callable(array($this, $method = "validate_{$filter}"))
                              || is_callable(array($this, $method = "validate_{$filterSynonym}"))):
                            $validationPassed = $this->$method($fieldValue, $argsSynonyms);
                            if (!$validationPassed) {
                                $validationErrorMsg[] = $fieldFilter['errormsg'];
                                $validationErrorMsg[] =
                                        $this->_getValidationErrorMsg($filter);
                            }
                            break;
                        default:
                            $validationPassed = FALSE;
                            $validationErrorMsg[] =
                                    $this->_getValidationErrorMsg('inexistent_validation');
                    }
                }

                if (!$validationPassed) {
                    foreach($validationErrorMsg as $errorMsg) {
                        if ($errorMsg != '') {
                            $this->_validationErrorLog[] = [
                                'args' => $args,
                                'errormsg' => $errorMsg,
                                'field' => $field,
                                'filter' => $filter,
                                'value' => (string) $fieldValue, //$this->_getFieldValueFromInput($field, $input),
                            ];
                            break;
                        }
                    }
                }
            }
        }

        return (count($this->_validationErrorLog) > 0) ? FALSE : TRUE;
    }

    /**
     * Sanitize the string by urlencoding characters.
     *
     * Usage: '<index>' => 'urlencode'
     *
     * @param string $value
     * @param array  $args
     *
     * @return string
     */
    protected function sanitize_urlencode($value, $args = NULL)
    {
        return filter_var($value, FILTER_SANITIZE_ENCODED);
    }

    /**
     * Filter out all HTML tags except the defined basic tags.
     *
     * @param string $value
     * @param array  $args
     *
     * @return string
     */
    protected function sanitize_basichtmltags($value, $args = NULL)
    {
        return strip_tags($value, $this->_basicHTMLTags);
    }

    /**
     * Sets default value if input is NULL
     *
     * @param string $value
     * @param array  $args
     *
     * @return string
     */
    protected function sanitize_default($value, $args = NULL)
    {
        return ($value === NULL || $value === '') ? $args[0] : $value;
    }

    /**
     * Sanitize the string by removing illegal characters from emails.
     *
     * Usage: '<index>' => 'sanitize_email'
     *
     * @param string $value
     * @param array  $args
     *
     * @return string
     */
    protected function sanitize_email($value, $args = NULL)
    {
        return filter_var($value, FILTER_SANITIZE_EMAIL);
    }

    /**
     * Sanitize the string by removing illegal characters from float numbers.
     *
     * @param string $value
     * @param array  $args
     *
     * @return string
     */
    protected function sanitize_float($value, $args = NULL)
    {
        return filter_var($value, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
    }

    /**
     * Sanitize the string by converting HTML characters to their HTML entities.
     *
     * Usage: '<index>' => 'htmlencode'
     *
     * @param string $value
     * @param array  $args
     *
     * @return string
     */
    protected function sanitize_htmlencode($value, $args = NULL)
    {
        return filter_var($value, FILTER_SANITIZE_SPECIAL_CHARS);
    }

    /**
     * Sanitize the string by converting to lowercase.
     *
     * Usage: '<index>' => 'htmlencode'
     *
     * @param string $value
     * @param mixed  $args
     *
     * @return string
     */
    protected function sanitize_lowercase($value, $args = NULL)
    {
        return strtolower($value);
    }

    /**
     * Replace noise words in a string (http://tax.cchgroup.com/help/Avoiding_noise_words_in_your_search.htm).
     *
     * Usage: '<index>' => 'noise_words'
     *
     * @param string $value
     * @param array  $args
     *
     * @return string
     */
    protected function sanitize_noisewords($value, $args = NULL)
    {
        $value = preg_replace('/\s\s+/u', chr(32), $value);

        $value = " $value ";

        $words = explode(',', $this->_enNoiseWords);

        foreach ($words as $word) {
            $word = trim($word);

            $word = " $word "; // Normalize

            if (stripos($value, $word) !== false) {
                $value = str_ireplace($word, chr(32), $value);
            }
        }

        return trim($value);
    }

    /**
     * Remove all known punctuation from a string.
     *
     * Usage: '<index>' => 'nopunctuation'
     *
     * @param string $value
     * @param array  $args
     *
     * @return string
     */
    protected function sanitize_nopunctuation($value, $args = NULL)
    {
        return preg_replace("/(?![.=$'€%-])\p{P}/u", '', $value);
    }

    /**
     * Sanitize the string by removing illegal characters from numbers.
     *
     * @param string $value
     * @param array  $args
     *
     * @return string
     */
    protected function sanitize_numeric($value, $args = NULL)
    {
        return filter_var($value, FILTER_SANITIZE_NUMBER_INT);
    }

    /**
     * Sanitize the string by removing any script tags.
     *
     * Usage: '<index>' => 'sanitize_string'
     *
     * @param string $value
     * @param array  $args
     *
     * @return string
     */
    protected function sanitize_string($value, $args = NULL)
    {
        return filter_var($value, FILTER_SANITIZE_STRING);
    }

    /**
     * Trims leading and trailing spaces.
     *
     * Usage: '<index>' => 'sanitize_string'
     *
     * @param string $value
     * @param array  $args
     *
     * @return string
     */
    protected function sanitize_trim($value, $args = NULL)
    {
        return ($args == NULL) ? trim($value) : trim($value, implode('', $args));
    }

    /**
     * Sanitize the string by converting to uppercase.
     *
     * Usage: '<index>' => 'uppercase'
     *
     * @param string $value
     * @param mixed  $args
     *
     * @return string
     */
    protected function sanitize_uppercase($value, $args = NULL)
    {
        return strtoupper($value);
    }

    /**
     * Convert the provided numeric value to a whole number.
     *
     * @param string $value
     * @param array  $args
     *
     * @return string
     */
    protected function sanitize_whole_number($value, $args = NULL)
    {
        return intval($value);
    }

    // ** ------------------------- Validators ------------------------------------ ** //
    /**
     * Determine if the provided value contains only alpha characters.
     *
     * Usage: '<index>' => 'alphabetic'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_alphabetic($value, $args = NULL)
    {
        return (preg_match(
                    '/^([a-zÀÁÂÃÄÅÇÈÉÊËÌÍÎÏÒÓÔÕÖßÙÚÛÜÝàáâãäåçèéêëìíîïðòóôõöùúûüýÿ])+$/i'
                    , $value)
                === 1);
    }

    /**
     * Determine if the provided value contains only alpha-numeric characters.
     *
     * Usage: '<index>' => 'alphanumeric'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_alphanumeric($value, $args = NULL)
    {
        return (preg_match(
                    '/^([a-zÀÁÂÃÄÅÇÈÉÊËÌÍÎÏÒÓÔÕÖßÙÚÛÜÝàáâãäåçèéêëìíîïðòóôõöùúûüýÿ0-9])+$/i'
                    , $value)
                === 1);
    }

    /**
     * Determine if the provided value is a PHP accepted boolean.
     *
     * Usage: '<index>' => 'boolean'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_boolean($value, $args = NULL)
    {
        return ($value === TRUE || $value === FALSE);
    }

    /**
     * Determine if the input is a valid credit card number.
     *
     * See: http://stackoverflow.com/questions/174730/what-is-the-best-way-to-validate-a-credit-card-in-php
     * Usage: '<index>' => 'creditcard'
     *
     * @param string $field
     * @param array  $input
     *
     * @return mixed
     */
    protected function validate_creditcard($value, $args = NULL)
    {
        $number = preg_replace('/\D/', '', $value);

        $number_length = function_exists('mb_strlen')
                ? mb_strlen($number)
                : strlen($number);

        $parity = $number_length % 2;

        $total = 0;

        for ($i = 0; $i < $number_length; ++$i) {
            $digit = $number[$i];

            if ($i % 2 == $parity) {
                $digit *= 2;

                if ($digit > 9) {
                    $digit -= 9;
                }
            }

            $total += $digit;
        }

        return ($total % 10 == 0);
    }

    /**
     * Determine if the provided input is a valid date (ISO 8601).
     *
     * Usage: '<index>' => 'date'
     *
     * @param string $field
     * @param string $input date ('Y-m-d') or datetime ('Y-m-d H:i:s')
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_date($value, $args = NULL)
    {
        return ((date('Y-m-d', strtotime($value)) == $value)
                || (date('Y-m-d H:i:s', strtotime($value))
                        == $value));
    }

    /**
     * Determine if the provided email is valid.
     *
     * Usage: '<index>' => 'valid_email'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_email($value, $args = NULL)
    {
        return (filter_var($value, FILTER_VALIDATE_EMAIL) !== FALSE);
    }

    /**
     * Check if the specified key is present and not empty.
     *
     * Usage: '<index>' => 'notempty'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_empty($value, $args = NULL)
    {
        return empty($value);
    }

    /**
     * Determine if the provided value starts with param.
     *
     * Usage: '<index>' => 'starts,Z'
     *
     * @param string $field
     * @param array  $input
     *
     * @return mixed
     */
    protected function validate_endswith($value, $args = NULL)
    {
        return (count($args) == 0
                || (strpos($value, $args[0])
                    === (strlen($value) - strlen($args[0])))
                || (isset($args[1]) && $args[1] === 'caseinsensitive'
                    && (stripos($value, $args[0])
                        === (strlen($value) - strlen($args[0]))))
                );
    }

    /**
     * Determine if the provided field value equals current field value.
     *
     * Usage: '<index>' => 'equalsfield,Z'
     *
     * @param string $field
     * @param string $input
     * @param string $args field to compare with
     *
     * @return mixed
     */
    protected function validate_equalsfield($value, $args = NULL)
    {
        return (isset($input[$args[0]]) &&
                    $value == $input[$args[0]]);
    }

    /**
     * Determine if the provided value length matches a specific value.
     *
     * Usage: '<index>' => 'exact_len,5'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_exactlen($value, $args = NULL)
    {
        return (isset($args[0]) && (function_exists('mb_strlen')
                     ? (mb_strlen($value) == (int) $args[0])
                     : (strlen($value) == (int) $args[0])));
    }

    /**
     * Always returns false, can be used to forcibly fail a field.
     *
     * Usage: '<index>' => 'validate_fail'
     *
     * @param string $field never used, kept so that calls remain standardized
     * @param array  $input never used, kept so that calls remain standardized
     * @param array  $args  never used, kept so that calls remain standardized
     *
     * @return bool  always FALSE
     */
    protected function validate_fail($value = NULL, $args = NULL)
    {
        return FALSE;
    }

    /**
     * check the uploaded file for extension
     * for now checks onlt the ext should add mime type check.
     *
     * Usage: '<index>' => 'starts,Z'
     *
     * @param string $field
     * @param array  $input
     *
     * @return mixed
     */
    protected function validate_fileextension($value, $args = NULL)
    {
        return ($value['error'] === 4)
                || in_array(pathinfo($value['name'])['extension']
                        , $args);
    }

    /**
     * Determine if the provided value is a valid float.
     *
     * Usage: '<index>' => 'float'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_float($value, $args = NULL)
    {
        return (filter_var($value, FILTER_VALIDATE_FLOAT) !== FALSE);
    }

    /**
     * Determine if the provided field value is a valid GUID (v4)
     *
     * Usage: '<index>' => 'guidv4'
     *
     * @param string $field
     * @param string $input
     * @param string $args field to compare with
     * @return mixed
     */
    protected function validate_guidv4($value, $args = NULL)
    {
        return (preg_match(
                        '/\{?[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}\}?$/'
                        , $value)
                    === 1);
    }

    /**
     * Determine if the provided value is a valid IBAN (international bank
     * account number)
     *
     * Usage: '<index>' => 'iban'
     *
     * @param string $field
     * @param array  $input
     *
     * @return mixed
     */
    protected function validate_iban($value, $args = NULL)
    {
        static $character = array(
            'A' => 10, 'C' => 12, 'D' => 13, 'E' => 14, 'F' => 15, 'G' => 16,
            'H' => 17, 'I' => 18, 'J' => 19, 'K' => 20, 'L' => 21, 'M' => 22,
            'N' => 23, 'O' => 24, 'P' => 25, 'Q' => 26, 'R' => 27, 'S' => 28,
            'T' => 29, 'U' => 30, 'V' => 31, 'W' => 32, 'X' => 33, 'Y' => 34,
            'Z' => 35, 'B' => 11
        );

        if (!preg_match("/\A[A-Z]{2}\d{2} ?[A-Z\d]{4}( ?\d{4}){1,} ?\d{1,4}\z/", $value)) {
            return FALSE;
        }

        $iban = str_replace(' ', '', $value);
        $iban = substr($iban, 4).substr($iban, 0, 4);
        $iban = strtr($iban, $character);

        return (bcmod($iban, 97) == 1);
    }

    /**
     * Verify that a value is contained within the pre-defined value set.
     *
     * Usage: '<index>' => 'inlist:value,value,value'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_inlist($value, $args = NULL)
    {
        return (in_array(trim(strtolower($value)), $args));
    }

    /**
     * Determine if the provided value is a valid integer.
     *
     * Usage: '<index>' => 'integer'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_integer($value, $args = NULL)
    {
        return (filter_var($value, FILTER_VALIDATE_INT) !== FALSE);
    }

    /**
     * Determine if the provided value is a valid IP address.
     *
     * Usage: '<index>' => 'valid_ip'
     *
     * @param string $field
     * @param array  $input
     *
     * @return mixed
     */
    protected function validate_ip($value, $args = NULL)
    {
        return (filter_var($value, FILTER_VALIDATE_IP) !== FALSE);
    }

    /**
     * Determine if the provided value is a valid IPv4 address.
     *
     * Usage: '<index>' => 'valid_ipv4'
     *
     * @param string $field
     * @param array  $input
     *
     * @return mixed
     *
     * @see http://pastebin.com/UvUPPYK0
     */

    /*
     * What about private networks? http://en.wikipedia.org/wiki/Private_network
     * What about loop-back address? 127.0.0.1
     */
    protected function validate_ipv4($value, $args = NULL)
    {
        return (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
                    !== FALSE);
    }

    /**
     * Determine if the provided value is a valid IPv6 address.
     *
     * Usage: '<index>' => 'valid_ipv6'
     *
     * @param string $field
     * @param array  $input
     *
     * @return mixed
     */
    protected function validate_ipv6($value, $args = NULL)
    {
        return (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
                    !== FALSE);
    }

    /**
     * Json validatior.
     *
     * Usage: '<index>' => 'valid_json_string'
     *
     * @param string $field
     * @param array  $input
     *
     * @return mixed
     */
    protected function validate_jsonstring($value, $args = NULL)
    {
        return (is_string($value) && is_object(json_decode($value)));
    }

    /**
     * Determine if the provided value length is less or equal to a specific value.
     *
     * Usage: '<index>' => 'max_len,240'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_maxlen($value, $args = NULL)
    {
        return (function_exists('mb_strlen')
                    ? (mb_strlen($value) <= (int) $args[0])
                    : (strlen($value) <= (int) $args[0]));
    }

    /**
     * Determine if the provided numeric value is lower or equal to a specific value.
     *
     * Usage: '<index>' => 'max_numeric,50'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_maxnumeric($value, $args = NULL)
    {
        return (is_numeric($value)
                    && is_numeric($args[0])
                    && ($value <= $args[0]));
    }

    /**
     * Determine if the provided input meets age requirement (ISO 8601).
     *
     * Usage: '<index>' => 'min_age,13'
     *
     * @param string $field
     * @param string $input date ('Y-m-d') or datetime ('Y-m-d H:i:s')
     * @param string $args int
     *
     * @return mixed
     */
    protected function validate_minage($value, $args = NULL)
    {
        $cdate1 = new DateTime(date('Y-m-d', strtotime($value)));
        $today = new DateTime(date('d-m-Y'));

        $interval = $cdate1->diff($today);

        return ($interval->y >= $args[0]);
    }

    /**
     * Determine if the provided value length is more or equal to a specific value.
     *
     * Usage: '<index>' => 'min_len,4'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_minlen($value, $args = NULL)
    {
        return (function_exists('mb_strlen')
                    ? (mb_strlen($value) >= (int) $args[0])
                    : (strlen($value) >= (int) $args[0]));
    }

    /**
     * Determine if the provided numeric value is higher or equal to a specific value.
     *
     * Usage: '<index>' => 'min_numeric,1'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     * @return mixed
     */
    protected function validate_minnumeric($value, $args = NULL)
    {
        return (is_numeric($value)
                    && is_numeric($args[0])
                    && ($value >= $args[0]));
    }

    /**
     * Check if the specified key is present and not empty.
     *
     * Usage: '<index>' => 'notempty'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_notempty($value, $args = NULL)
    {
        return !empty($value);
    }

    /**
     * Verify that a value is NOT contained within the pre-defined value set.
     * OUTPUT: will NOT show the list of values.
     *
     * Usage: '<index>' => 'doesnt_contain_list,value;value;value'
     *
     * @param string $field
     * @param array  $input
     *
     * @return mixed
     */
    protected function validate_notinlist($value, $args = NULL)
    {
        return (!in_array(trim(strtolower($value)), $args));
    }

    /**
     * Determine if the provided value is a valid number or numeric string.
     *
     * Usage: '<index>' => 'numeric'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_numeric($value, $args = NULL)
    {
        return (is_numeric($value));
    }

    /**
     * Always returns true, can be used as place holder to have at least one
     * validation filter.
     *
     * Usage: '<index>' => 'validate_pass'
     *
     * @param string $field never used, kept so that calls remain standardized
     * @param array  $input never used, kept so that calls remain standardized
     * @param array  $args  never used, kept so that calls remain standardized
     *
     * @return bool  always TRUE
     */
    protected function validate_pass($value = NULL, $args = NULL)
    {
        return TRUE;
    }

    /**
     * Determine if the input is a valid human name [Credits to http://github.com/ben-s].
     *
     * Usage: '<index>' => 'valid_name'
     *
     * @param string $field
     * @param array  $input
     *
     * @return bool
     */
    protected function validate_personname($value, $args = NULL)
    {
        return (preg_match(
                        '/^([a-zÀÁÂÃÄÅÇÈÉÊËÌÍÎÏÒÓÔÕÖßÙÚÛÜÝàáâãäåçèéêëìíîïñðòóôõöùúûüýÿ\s\'-])+$/i'
                        , $value)
                    === 1);
    }

    /**
     * Determine if the provided value is a valid phone number.
     *
     * Usage: '<index>' => 'phone_number'
     *
     * @param string $field
     * @param array  $input
     *
     * @return mixed
     *
     * Examples:
     *
     *    555-555-5555: valid
     *    5555425555: valid
     *    555 555 5555: valid
     *    1(519) 555-4444: valid
     *    1 (519) 555-4422: valid
     *    1-555-555-5555: valid
     *    1-(555)-555-5555: valid
     */
    protected function validate_phonenumber($value, $args = NULL)
    {
        return (preg_match('/^(\d[\s-]?)?[\(\[\s-]{0,2}?\d{3}[\)\]\s-]{0,2}?\d{3}[\s-]?\d{4}$/i'
                        , $value));
    }

    /**
     * Custom regex validator.
     *
     * Usage: '<index>' => 'regex,/your-regex-expression/'
     *
     * @param string $field
     * @param array  $input
     *
     * @return mixed
     */
    protected function validate_regex($value, $args = NULL)
    {
        return (preg_match($args[0], $value));
    }

    /**
     * Check if the specified key is present and not empty.
     *
     * Usage: '<index>' => 'required'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_required($value, $args = NULL)
    {
        return !($value === NULL || $value === '');
    }

      /**
       * checks if a file was uploaded.
       *
       * Usage: '<index>' => 'required_file'
       *
       * @param  string $field
       * @param  array $input
       *
       * @return mixed
       */
      protected function validate_requiredfile($value, $args = NULL)
      {
          return ($value['error'] === 4);
      }

    /**
     * Determine if the provided value starts with param.
     *
     * Usage: '<index>' => 'starts,Z'
     *
     * @param string $field
     * @param array  $input
     *
     * @return mixed
     */
    protected function validate_startswith($value, $args = NULL)
    {
        return (count($args) == 0
                || (strpos($value, $args[0]) === 0)
                || (isset($args[1]) && $args[1] === 'caseinsensitive'
                    && stripos($value, $args[0]) === 0));
    }

    /**
     * Determine if the provided input is likely to be a street address using weak detection.
     *
     * Usage: '<index>' => 'street_address'
     *
     * @param string $field
     * @param array  $input
     *
     * @return mixed
     */
    protected function validate_streetaddress($value, $args = NULL)
    {
        // Theory: 1 number, 1 or more spaces, 1 or more words
        $hasLetter = preg_match('/[a-zA-Z]/', $value);
        $hasDigit = preg_match('/\d/', $value);
        $hasSpace = preg_match('/\s/', $value);

        return ($hasLetter && $hasDigit && $hasSpace);
    }

    /**
     * Determine if the provided value is a valid URL.
     *
     * Usage: '<index>' => 'valid_url'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_url($value, $args = NULL)
    {
        return (filter_var($value, FILTER_VALIDATE_URL) !== FALSE);
    }

    /**
     * Determine if a URL exists & is accessible.
     *
     * Usage: '<index>' => 'url_exists'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    public function version()
    {
        return self::VERSION;
    }

    /**
     * Determine if a URL exists & is accessible.
     *
     * Usage: '<index>' => 'url_exists'
     *
     * @param string $field
     * @param array  $input
     * @param null   $args
     *
     * @return mixed
     */
    protected function validate_urlexists($value, $args = NULL)
    {
        $url = parse_url(strtolower($value));

        if (isset($url['host'])) {
            $url = $url['host'];
        }

        if (function_exists('checkdnsrr')) {
            return checkdnsrr($url);
        } else {
            return (gethostbyname($url) != $url);
        }
    }

    /**
     * Trims whitespace only when the value is a scalar.
     *
     * @param mixed $value
     *
     * @return mixed
     */
    private function trimScalar($value)
    {
        if (is_scalar($value)) {
            $value = trim($value);
        }

        return $value;
    }
} // EOC
