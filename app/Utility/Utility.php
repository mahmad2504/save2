<?php
namespace App\Utility;
class  Utility
{
    public static function Console($id , $msg) 
    {
	    if(\App::runningInConsole())
		{
			echo $msg."\n";
			return;
		}
		
    	$msg = str_replace('"', "'", $msg);
    	
		echo "id: $id" . PHP_EOL;
		echo "data: {\n";
		echo "data: \"msg\": \"$msg\", \n";
		echo "data: \"id\": $id\n";
		echo "data: }\n";
		echo PHP_EOL;
		ob_flush();
		flush();
    }
    public static function GetContentSize($url) 
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_FILETIME, true);
        curl_setopt($curl, CURLOPT_NOBODY, true);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HEADER, true);
        $header = curl_exec($curl);
        $info = curl_getinfo($curl);
        curl_close($curl);
        return $info['download_content_length'];
    }
}