## Valigator: Stand-alone PHP Class for Data Sanitization and Validation
Lovers of minimalism, rejoice! Valigator is a stand-alone PHP class for data sanitization and validation. It has no library dependencies, implements programmer-friendly filter syntax, and is highly flexible. Its just one single class file, include it and you are already on the move!

### Valigator, huh?
PHP API frameworks are picking up, fast. They are wonderfully minimalist, speedy, and vastly preferred over powerful yet sometimes clunky larger frameworks. To implement validations in API frameworks and projects, large vendor sources have to be installed, adding unnecessary additions to code-base and complexity. Valigator was created to address specifically that. And there's nothing that stops you from using Valigator in non-API projects. Go ahead, you'll love it!

#####    Valigator Checklist:
      ✓ PHP (5.5.*, 5.6.*, 7.*)
      ✓ Simple
      ✓ Flexible
      ✓ Stand-alone
      ✓ Programmer-friendly
      ✓ Data Sanitization
      ✓ Data Validation

PS: Slim Framework 3 is awesome!

### Yet Another Vali[dg]ator
Maybe. Maybe not. Yeah, Valigator draws inspiration from some of the good, nay, great ones. And adds its own good bits too. Just to get you interested: Filter Aliasing, Multiple Arguments, custom Labels, custom Validation Error Messages and more.

## Anatomy of Valigator
### Terminology
 * **field**  
The name of the data to which filters are mapped. Typically variable names in a POST request.  A field may be mapped to no, one or multiple sanitization filters. A field may be mapped to no, one or multiple validation filters. Case-sensitive. For example, `loginId` is not the same as `loginid`.
 * **value**  
The value of the field on which the filters run. Typically mapped to variable names in a POST request. Case-sensitive unless made case-insensitive by filters running on it. For example, `email` filter doesn't care if the value passed has upper or lower case characters.
 * **filter**  
What some know as *rules*, Valigator prefers to call them *filters*. Because there are sanitization filters and validation filters, simple. Case-insensitive. For example, mis-typing `required` as `Required` makes no difference.
 * **args**  
Arguments passed to filters. You may pass no, one or multiple arguments to a filter. Case-insensitive, unless made case-sensitive by filters requiring it. For example, `startswith` filter can validate if a field value starts with characters passed as a case-sensitive argument.
 * **sanitization**  
Sanitization filters are known as simply 'sanitizations'. Sanitizations never error out so never emit any error messages.
 * **validation**  
And vanitization filters are known as simply 'validations'. A validation can either pass or fail. If it fails, it emits one error message.
 * **label**  
Human-readable label of the field which the programmer can set. If not set, labels default to upper-cased words of the field variable-name. For example, field `loginId` by default will be labelled `Login Id` (rad, isn't it!), but can be renamed by programmer to `Registered Login ID`. Variable-names of following patterns are automatically detected: *snake_case*, *camelCase*, *PascalCase* and *train-case*. Some default label examples:
  * `token` becomes `Token`
  * `project_title` becomes `Project Title`
  * `book-1` becomes `Book 1`
  * `debitCardNumber` becomes `Debit Card Number`
  * `FAQAnswer6` becomes `FAQ Answer 6`
  * `SuspenseAccount#` becomes `Suspense Account #`
 * **errormsg**  
Error messages emitted by validations (one per validation). Can be overwritten with custom error messages by the programmer per field per validation. Error messages may contain some special tags which will be replaced dynamically:  
  * `{field}` or `{label}` is replaced with label of the field
  * `{fieldlineage}` or `{labellineage}` is replaced with label of the full field hierarchy in reverse order (as in `Node 3 of Node 2 of Node 1`
  * `{fieldlineagef}` or `{labellineagef}` is replaced with label of the full field hierarchy in forward order (as in `Node 1.Node 2.Node 3`
  * `{value}` is replaced with value of the field
  * `{filter}` is replaced with name of the filter
  * `{args}` or `{parms}` is replaced with delimited string of concatenated arguments to the filter
  * `{arg1}`, ..., `{argn}` or `{parm1}`, ..., `{parmn}` are replaced with individual arguments to the filter if they exist (note that there is no {arg0} or {parm0})

### The Gears and Wheels
Its easier to proceed from here with an example. Lets say we want to validate the following fields:

 * loginId: required and must be an email ID
 * name: required and must be a name
 * creditCardNumber: not mandatory, but if provided must be a valid credit card number
 * addressPINCode: not mandatory, but if provided must be a 6-digit number

Yes, you noticed it, camelCase is just my preference.

Now lets say we are receiving the following data in an array (if you are not receiving the data in an array, you will need to create an array):
``` php
<?php
// iteration 1
$inputData = [
  'salutation' => 'Mr.',                               // we aren't interested in validating this
  'loginId' => '',                                     // invalid data as it is empty
                                                       // notice that 'name' is missing
  'creditCardNumber' => '0001-0001-0001-ABCD',         // not a valid credit card number
                                                       // notice that 'addressPINCode' is missing
];
```
Lets now create filters based on the data validation requirements we have, and add a few other useful things. Please read Important Notes in the code comments.
``` php
<?php
$myFilters = [
  'loginId:"Retail User ID"' => [                      // overrides default label 'Login Id'
    'sanitizations' => 'trim',                         // 'trim' is a popular filter, works exactly
                                                       // like the PHP in-built trim()
    'validations' => 'required|email',                 // multiple validation filters
  ],
  'name:"Full Name"' => [                              // overrides default 'Name'
    'sanitization' => 'trim',                          // singular 'sanitization' works too
    'validation' => 'required|personname',             // singular 'validation' works too
  ],
  'creditCardNumber' => [
                                                       // label defaults to 'Credit Card Number'
    'sanitizations' => 'trim|numeric',                 // multiple sanitization filters
    'validations' => 'creditcard',                     // if present, must be credit card number
  ],
  'addressPINCode:"Indian PIN Code"' => [              // overrides default 'Address PIN Code'
                                                       // no sanitization filters here
    'validations' => 'numeric|exactlen:6',             // if present, must be numeric of exactly 6
                                                       // characters length
  ],
];

// Important Notes:
//  1. 'loginId', 'name', 'creditCardNumber' and 'addressPINCode' are our **fields** of
//     interest
//  2. Field names are case-sensitive: 'loginId' is not the same as 'loginid'
//  3. Important understanding about filters:
//     a. Sanitization filters will modify input, and will never emit errors
//     b. Validation filters will never modify input, but can emit errors
//  4. The order of running filters is as follows:
//     a. All sanitizations first (if they exist) in order: 'loginId' to 'addressPINCode'
//     b. Then all validations (if they exist) in order:  'loginId' to 'addressPINCode'
//  5. If there are validation errors, they will be reported in exactly the same order, so
//     if you want some errors to be reported higher than the others, place the field higher
//  6. You can use the following keywords interchangeably, whatever makes you comfortable:
//     a. 'sanitization' <=> 'sanitizations'
//     b. 'validation' <=> 'validations'
//  7. Multiple filters can be set for each field, for sanitizations or validations, the
//     delimiter is '|'. Filters are run in the same order from left to right. Output of first
//     sanitization filter is passed to the second one, output of second to the third and so on.
//     Output of sanitization is sent to validation filters.
//  8. For most validation filters except 'required', if input is absent or empty, validation
//     will pass. Simply add 'required' filter to the beginning of validation filters if the
//     value must be present.
```
Now lets run the validator:
``` php
<?php
require 'Valigator.php';                               // point to the right path, or autoload

$myValigator = new \Fishfin\Valigator($myFilters);

$validationResults = $myValigator->run($inputData);    // run() does sanitizations, then validations

if ($validationResults === FALSE) {                    // at least one validation failed
  $myValidationErrorsArray = $myValigator->getValidationErrors();
} else {                                               // all validations passed
  $sanitizedInputData = $validationResults;
}

// For iteration 1, following will be the results:
// $validationResults:
//   FALSE
// $myValidationErrorsArray:
//   ["Retail User ID is required",
//    "Full Name is required",
//    "Credit Card Number does not contain a valid credit card number"]
```
Lets try next iteration with slightly modified input.
``` php
<?php
require 'Valigator.php';                               // for brevity, we will not show this in next
                                                       // iteration
// iteration 2
$inputData = [
  'salutation' => 'Mr.',                               // still not interested in validating this
  'loginId' => 'user',                                 // still not okay, not an email
  'name' => 'Ruskin Bond 5',                           // what's a numeric doing in a name?
  'creditCardNumber' => '0001-0001-0001-0001',         // does not satisfy credit card last digit logic
  'addressPINCode' => 'A123456',                       // not a numeric, not 6 digits
];

$myValigator = new \Fishfin\Valigator($myFilters);     // block start
                                                       // for brevity, we will not show this block in next
$validationResults = $myValigator->run($inputData);    // iteration

if ($validationResults === FALSE) {
  $myValidationErrorsArray = $myValigator->getValidationErrors();
} else {
  $sanitizedInputData = $validationResults;
}                                                      // block end

// Results for iteration 2:
// $validationResults:
//   FALSE
// $myValidationErrorsArray:
//   ["Retail User ID is not a valid email address",
//    "Full Name does not seem to contain a person's name",
//    "Credit Card Number does not contain a valid credit card number",
//    "Indian PIN Code may only contain numeric characters",
//    "Indian PIN Code must be exactly 6 characters long"]
// Nice, yeah?
```
Time for iteration 3:
``` php
<?php
// iteration 3
$inputData = [
  'salutation' => 'Mr.',                               // whatever
  'loginId' => 'user@example.com',                     // looks okay now
  'name' => 'Ruskin Bond ',                            // notice additional blank at the end
  'creditCardNumber' => '4111=1111=1111=1111',         // is actually a valid sample Visa CC number
                                                       // notice '=' symbol instead of hyphens or blanks
  'addressPINCode' => '1234567',                       // not 6 digits
];

// Results:
// $validationResults:
//   FALSE
// $myValidationErrorsArray:
//   ["Indian PIN Code must be exactly 6 characters long"]
// No error on credit card number, because it was sanitized for numbers! More on this later.
```

And finally...
``` php
<?php
// iteration 4
$inputData = [
  'salutation' => 'Mr.',
  'loginId' => 'user@example.com',
  'name' => 'Ruskin Bond ',
  'creditCardNumber' => '4111=1111=1111=1111',
  'addressPINCode' => '123456',                        // looks good now
];

// Results:
// $validationResults:
//   TRUE
// $sanitizedInputData:
//   {"salutation":"Mr.",
//    "loginId":"user@example.com",
//    "name":"Ruskin Bond",
//    "creditCardNumber":"4111111111111111",
//    "addressPINCode":"123456"}
// Did you notice the name was sanitized by removing leading and trailing blanks? That was because
// of the 'trim' sanitization. Notice how '=' was removed because of the 'numeric' sanitization.
// All validations passed this time, phew!
```
### The Bells and Whistles
Now that you are comfortable with the basics, lets move on to some advanced stuff. Its advanced, but fret not, semantics are crazy easy!
#### Multiple Filters
You already know how to run multiple filters: the pipe '|'
```
'filter1|filter2|filter3'
```
#### Arguments to Filters
All positional arguments after ':', delimited by ',', can it get simpler than this?
```
'filter1:arg1,arg2,arg3'
```
If you are a programmer, you will know what to expect in positional arguments. That's your clue.
#### Custom Error Messages for Validation Filters
Validation filters emit default error messages if data does not match the filter. If you don't like the default messages, make your own! After arguments, put a ';' and start your custom error message, with single or double quotes.
```
'filter1:arg1,arg2;"My very own validation error message!"'
'filter2;\'And I\'ll change this one\'s too!\''
```
Notice how filter2 had no arguments, so ':' was not required. If the error message itself doesn't contain any special characters, like the single or double quotes, ':' or ';', why, you may not even put the wrapping quotes!
#### Custom Error Messages with Special Tags
If you liked the custom error message, you will like this even better. `{field}`, `{value}`, `{filter}`, `{args}`, `{arg1}` ... `{argn}` are all special tags in validation error messages.  
```
'filter1:arg1,arg2;"{field} with value {value} failed filter {filter} with attributes {args}"'
'filter2:arg1,arg2;"Maybe {field} didn't like {filter} with that parameter {arg2}"'
```
Just for fun, let's say the validation filter was called 'wildfur', with args 'yellow,striped'. Let's say the field for which it was run was 'animal' whose label was 'Animal' (either set automatically or explicity with 'label' key) and value of the field was 'cheetah'.
```
'wildfur:yellow,striped;"{field} with value {value} may not have liked {filter} with attributes {args}, especially {arg2}"'
```
would emit error message:
```
'Animal with value cheetah may not have liked wildfur with attributes yellow, striped, especially striped'
```
#### Commenting out Individual Filters
Just put a '/' to comment out a filter from running. It will be very useful in debugging, I assure you.
```
'/filter1:arg1f1;"This filter will not run"|filter2:arg1f2;"This filter will run"'
```
#### Skipping Filter Blocks
Use special keyword 'skip' in filter list.
```
'filter1|skip|filter2:;"Skipping this and all after"|filter3:;"Skipping this too"'
'filter1|skip:all|filter2:;"Skipping this and all after"|filter3:;"Skipping this too"'
'filter1:;"Will run"|skip:2|filter2:"Skipping first"|filter3:;"Skipping second"|filter4:;"Will run"'
```
`skip` and `skip:all` means the same thing, whatever suits you.
#### Aliases of Popular Filters
Some popular filters and some arguments have aliases, because different programmers remember them as different names, programming quirks you see.
  * `alphabet` is the same as `alphabetic`
  * `boolean` is the same as `bool`
  * `integer` is the same as `int`
  * `numeric` is the same as `num` is the same as `number`
  * `string` is the same as `str`  
This list will be updated based on popular feedback.

### The Big List of Filters
#### Sanitization Filters
  * `basichtmltags` removes all HTML tags except basic tags like `<a>`, `<b>`, `<blockquote>`, `<br>`, `<code>`,
  `<dd>`, `<dl>`, `<em>`, `<hr>`, `<h1>`, `<h2>`, `<h3>`, `<h4>`, `<h5>`, `<h6>`, `<i>`, `<img>`, `<label>`, `<li>`,
  `<p>`, `<span>`, `<strong>`, `<sub>`, `<sup>` and `<ul>`.
  * `email` removes all illegal characters from email ids.
  * `float` removes all illegal characters from float numbers.
  * `htmlencode` converts HTML characters to their HTML entities, for eg. to `&` to `&#38;`, `'` to `&#39;`, `"` to
  `&#34;`, `<` to `&#60;`, `>` to `&#62;`.
#### Validation Filters

#### In-depth documentation is in progress, but so much so far should get you started easily! The PHP class is Production-ready.
