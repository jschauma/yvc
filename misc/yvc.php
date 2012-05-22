<?php
header('Content-type: text/html');
?>

<html>
  <head>
    <title>yvc -- check packages against known vulnerabilities</title>
  </head>
  <body>

  <h2>YVC Web Interface</h2>
  <hr>

<?php
$packages = $_GET['packages'];
if (isset($packages) && !empty($packages)) {
	$pkgs = preg_replace("/\s+/", "\n", $packages);

	$dsc = array(
		0 => array("pipe", "r"),
		1 => array("pipe", "w"),
	);

	$cwd = '/tmp';

	$process = proc_open('yvc', $dsc, $pipes, NULL, NULL);

	if (is_resource($process)) {
		fwrite($pipes[0], $pkgs);
		fclose($pipes[0]);

		$results = 0;

		foreach (preg_split("/\n/", stream_get_contents($pipes[1])) as $vul) {
			$fields = preg_split("/\s+/", $vul);
			if (count($fields) == 8) {
				$results++;
				if ($results == 1) {
					echo "  <h3>Vulnerable packages:</h3>";
					echo "  <ul>";
				}
				printf("    <li><b>%s</b> has a <em>%s</em> vulnerability, see <a href=\"%s\">%s</a></li>",
					$fields[1], $fields[4], $fields[7], $fields[7]);
			}
		}
		fclose($pipes[1]);

		if ($results > 0) {
			echo "  </ul>";
		} else {
			echo "No vulnerabilities found.";
		}
	}
	echo "  <hr>";
	echo "  <a href=\"yvc.php\">Back to check more packages</a>";
  } else {
?>
Enter package-version names (for example <em>perl-5.8.5_13</em>), one per line.<br>
  <form method="GET" name="yvc">
  <textarea cols="50" rows="10" name="packages">
  </textarea><br><br>
  <input type="submit" value='Check packages'>
  </form>
<?php
}
?>
  <hr>
  [<a href="http://www.netmeister.org/apps/yvc/">About yvc</a>]&nbsp;|&nbsp;[<a href="mailto:jschauma@yahoo-inc.com">Contact the Author</a>]
  </body>
</html>
