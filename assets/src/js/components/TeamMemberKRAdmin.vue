<template>
  <v-container fluid style="height:100%">
    <v-card style="height:100%">
      <v-card flat>
        <v-card-title>KR Admin</v-card-title>
        <v-data-table class="mr-3" :headers="headers">
          <template v-slot:body>
            <tbody>
              <tr>
                <td>1</td>
                <td>Joseph</td>
                <td></td>
                <td>KR Manager</td>
                <td></td>
                <td></td>
                <td></td>
              </tr>
            </tbody>
          </template>
        </v-data-table>
      </v-card>
    </v-card>
  </v-container>
</template>

<script>
export default {

  data: vm => ({
    headers: [{
      text: '#',
      align: 'left',
      value: '',
    },
    {
      text: 'Mega Name',
      value: 'mega_name',
    },
    {
      text: 'Team',
      value: 'team',
    },
    {
      text: 'Position',
      value: 'position',
    },
    {
      text: 'Start of Shift',
      value: 'start_of_shift',
    },
    {
      text: 'End of Shift',
      value: 'end_of_shift',
    },
    {
      text: 'Attendance',
      value: 'attendance',
    }
  ],
}),

}
</script>

<style lang="css">
</style>
