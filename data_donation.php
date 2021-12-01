<?php
//import ban_ip
include_once("php-ban-ip-main/banip.php");


//options
$send_email_option=true;
$email_array=array("email@gmx.de");

$dirpath = __DIR__ . "/log";
$delete_logs_after = Array(1,10); //Delete Logs (0/1) ->no/yes after (x) -> days. Ex. Array(1,10) -> yes after 10 days.




//Read post requests
$post_var = array_map(function($item) {
    return xss_clean($item);
}, $_POST);

//Check if folder exist

    if (!file_exists($dirpath)) {
        mkdir($dirpath, 0700);
    }

//Convert to json
$post_json_var = json_encode($post_var);

//write data down in file
$filepath  =$dirpath . "/" . date("d.m.Y"). ".txt";
writeinfile_append($filepath ,$post_json_var);

//secure file
secure_file_against_reading($filepath);


//send mail if option is set
if($send_email_option == true){
    sendmailtorecipients($email_array,"data_donation " . date("d.M.Y H-i-s") ,$post_json_var,$output=false);
}


//delete old data

//preperations
    //log cleaning?
    if($delete_logs_after[0] ==1){
        
        //Check and create folder
        $path = "log";
        if (!is_dir($path)) {
            mkdir($path, 0700, true);
        }
        delete_old_files("log", "*", $delete_logs_after[1]*86400);
    }




//functions
//#############################

function delete_old_files($dir_path, $filetype = "*", $delete_after_x_seconds = 86400){

    //Deletefunction
    
        //check folder exist
        if (!file_exists($dir_path)) {
            http_response_code(500);
            throw new Exception('Cleanfunction log: Folder does not exist.');
        }
    
    $dir_path .= "/";
    
                    //default 1 day
                    //8035200 sek ~3 monate
                    //5356800 sek ~ 2 Monate
                    //3456000 sek ~ 40 Tage
                    //2678400 sek ~ 1 Monat
                    //864000 sek ~ 10 tage
                    //259200 sek ~ 3 Tage
    
    /*** cycle through all files in the directory ***/
    foreach (glob($dir_path."*." . $filetype) as $file) {
        
    
                    $erg=time() - filemtime($file);
    
                    if($erg > $delete_after_x_seconds){
                        
                        
                        // Use unlink() function to delete a file  
                            if (!unlink($file)) { 
                                    
                                        echo ("$file cannot be deleted due to an error". "<br>"); 
    
                            }  
                        }
                       
    }
    
    
        
    return true;
    
    }

function sendmailtorecipients($contacts_array,$subject,$message,$output=false){
    // $contacts array
    //   $contacts = array("youremailaddress@yourdomain.com","youremailaddress@yourdomain.com");
    //....as many email address as you need
     
            foreach($contacts_array as $contact) {
            
            $to      =  $contact;
            mail($to, $subject, $message);
    
            //Outpu of sending message
            if($output == true){
                echo "keyit.php: Send mail to " . $to . "with the subject " . $subject . " and the text " . $message . "... <br>";
            }
            
            }
    
    
    }


function writeinfile_append($filename,$text){
    file_put_contents($filename, $text.PHP_EOL , FILE_APPEND | LOCK_EX);
}

function secure_file_against_reading($filename){
    chmod($filename, 0600);
}


function xss_clean($data)
{
// Fix &entity\n;
$data = str_replace(array('&amp;','&lt;','&gt;'), array('&amp;amp;','&amp;lt;','&amp;gt;'), $data);
$data = preg_replace('/(&#*\w+)[\x00-\x20]+;/u', '$1;', $data);
$data = preg_replace('/(&#x*[0-9A-F]+);*/iu', '$1;', $data);
$data = html_entity_decode($data, ENT_COMPAT, 'UTF-8');

// Remove any attribute starting with "on" or xmlns
$data = preg_replace('#(<[^>]+?[\x00-\x20"\'])(?:on|xmlns)[^>]*+>#iu', '$1>', $data);

// Remove javascript: and vbscript: protocols
$data = preg_replace('#([a-z]*)[\x00-\x20]*=[\x00-\x20]*([`\'"]*)[\x00-\x20]*j[\x00-\x20]*a[\x00-\x20]*v[\x00-\x20]*a[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2nojavascript...', $data);
$data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*v[\x00-\x20]*b[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2novbscript...', $data);
$data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*-moz-binding[\x00-\x20]*:#u', '$1=$2nomozbinding...', $data);

// Only works in IE: <span style="width: expression(alert('Ping!'));"></span>
$data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?expression[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
$data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?behaviour[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
$data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:*[^>]*+>#iu', '$1>', $data);

// Remove namespaced elements (we do not need them)
$data = preg_replace('#</*\w+:\w[^>]*+>#i', '', $data);

do
{
    // Remove really unwanted tags
    $old_data = $data;
    $data = preg_replace('#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i', '', $data);
}
while ($old_data !== $data);

// we are done...
return $data;
}
?>
