<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});

Route::get('/monitoringlist/update/{monitoringlist_id}', 'MonitoringListController@Sync')->name('syncmonitoringlist');   // View
Route::get('/monitoringlist/import/{monitoringlist_id}', 'MonitoringListController@Import')->name('importmonitoringlist');   // View
Route::get('/monitoringlist/show/{monitoringlist_id}', 'MonitoringListController@Show')->name('showmonitoringlist');   // View

Route::get('/cvelist/show/{monitoringlist_id}/{component_id}', 'CVEListController@Show')->name('showcvelist');   // View

Route::get('/cvedatabase/update/{rebuild?}/{debug?}','CVESourceController@Update')->name('svesourceupdate'); // optional parameters rebuild=1 debug=1

