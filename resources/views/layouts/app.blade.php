<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <!-- CSRF Token -->
    <meta name="csrf-token" content="{{ csrf_token() }}">

    <title>{{ config('app.name', 'Laravel') }}</title>
	<script src="{{ asset('js/app.js') }}" ></script>
    <!-- Scripts -->
   
    <!-- Fonts -->
    <link rel="dns-prefetch" href="//fonts.gstatic.com">
    <link href="https://fonts.googleapis.com/css?family=Nunito" rel="stylesheet">
	<link href="{{ asset('css/app.css') }}" rel="stylesheet">
    @yield('csslinks')
    <style>

	</style>
</head>
<body>
    <div id="app">
        <main class="py-4">
			<div style="display:none;" class="loading">Loading&#8230;</div>
			@yield('content')
			<footer style="text-align: center;width:90%;" class="container-fluid">
				<small style="color:grey" >CVE Management &#169; <a style="color:grey" href="mailto:Mumtaz_Ahmad@mentor.com">2019-20 Mentor Graphics - Siemens Business</a><br>
				<a href="mailto:Mumtaz_Ahmad@mentor.com">
					<i  class="far fa-envelope"></i>
				</a>
				
				<a href="https://www.linkedin.com/in/mumtazahmad2">
					<i class="fab fa-linkedin"></i>
				</a>
				<a href="https://github.com/mahmad2504/sos"> <span style="color:grey"></span>  
					<i class="fab fa-github"></i>
				</a>
				</small>
			</footer>
        </main>
    </div>
	<script>
		@yield('script')
		var dates = {
		convert:function(d) {
			// Converts the date in d to a date-object. The input can be:
			//   a date object: returned without modification
			//  an array      : Interpreted as [year,month,day]. NOTE: month is 0-11.
			//   a number     : Interpreted as number of milliseconds
			//                  since 1 Jan 1970 (a timestamp) 
			//   a string     : Any format supported by the javascript engine, like
			//                  "YYYY/MM/DD", "MM/DD/YYYY", "Jan 31 2009" etc.
			//  an object     : Interpreted as an object with year, month and date
			//                  attributes.  **NOTE** month is 0-11.
			return (
				d.constructor === Date ? d :
				d.constructor === Array ? new Date(d[0],d[1],d[2]) :
				d.constructor === Number ? new Date(d) :
				d.constructor === String ? new Date(d) :
				typeof d === "object" ? new Date(d.year,d.month,d.date) :
				NaN
			);
		},
		compare:function(a,b) {
			// Compare two dates (could be of any type supported by the convert
			// function above) and returns:
			//  -1 : if a < b
			//   0 : if a = b
			//   1 : if a > b
			// NaN : if a or b is an illegal date
			// NOTE: The code inside isFinite does an assignment (=).
			return (
				isFinite(a=this.convert(a).valueOf()) &&
				isFinite(b=this.convert(b).valueOf()) ?
				(a>b)-(a<b) :
				NaN
			);
		},
		inRange:function(d,start,end) {
			// Checks if date in d is between dates in start and end.
			// Returns a boolean or NaN:
			//    true  : if d is between start and end (inclusive)
			//    false : if d is before start or after end
			//    NaN   : if one or more of the dates is illegal.
			// NOTE: The code inside isFinite does an assignment (=).
		   return (
				isFinite(d=this.convert(d).valueOf()) &&
				isFinite(start=this.convert(start).valueOf()) &&
				isFinite(end=this.convert(end).valueOf()) ?
				start <= d && d <= end :
				NaN
			);
		},
		daysBetween(firstDate,secondDate)// works on date objects
		{
			const oneDay = 24 * 60 * 60 * 1000;
			return Math.round(Math.abs((firstDate - secondDate) / oneDay));
		}
	}
	</script>	
</body>
</html>
