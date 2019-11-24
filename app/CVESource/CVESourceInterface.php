<?php
namespace App\CVESource;

Interface CVESourceInterface
{
    public function GetCVEs($package,$version=null);
    public function GetPackageList();
    public function Update($rebuild=0);
    public function GetCVEDetail($cve);
}
